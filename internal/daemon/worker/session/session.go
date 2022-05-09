package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/session"
)

// ValidateSessionTimeout is the duration of the timeout when the worker queries the
// controller for the sessionId for which the connection is being requested.
const ValidateSessionTimeout = 90 * time.Second

var errMakeSessionCloseInfoNilCloseInfo = errors.New("nil closeInfo supplied to makeSessionCloseInfo, this is a bug, please report it")

// ConnInfo defines the information about a connection attached to a session
type ConnInfo struct {
	Id         string
	ConnCtx    context.Context
	ConnCancel context.CancelFunc
	Status     pbs.CONNECTIONSTATUS
	CloseTime  time.Time
}

// Info defines the information about a session
type Info struct {
	sync.RWMutex
	Id                    string
	SessionTls            *tls.Config
	Status                pbs.SESSIONSTATUS
	LookupSessionResponse *pbs.LookupSessionResponse
	ConnInfoMap           map[string]*ConnInfo
}

// Activate is a helper worker function that sends session activation request to the
// controller.
func Activate(ctx context.Context, sessClient pbs.SessionServiceClient, workerId, sessionId, tofuToken string, version uint32) (pbs.SESSIONSTATUS, error) {
	resp, err := sessClient.ActivateSession(ctx, &pbs.ActivateSessionRequest{
		SessionId: sessionId,
		TofuToken: tofuToken,
		Version:   version,
		WorkerId:  workerId,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error activating session: %w", err)
	}
	return resp.GetStatus(), nil
}

// Cancel is a helper worker function that sends session cancellation request to the
// controller.
func Cancel(ctx context.Context, sessClient pbs.SessionServiceClient, sessionId string) (pbs.SESSIONSTATUS, error) {
	resp, err := sessClient.CancelSession(ctx, &pbs.CancelSessionRequest{
		SessionId: sessionId,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error canceling session: %w", err)
	}
	return resp.GetStatus(), nil
}

// AuthorizeConnection is a helper worker function that sends connection
// authorization request to the controller. It is called by the worker handler after a
// connection has been received by the worker, and the session has been validated.
func AuthorizeConnection(ctx context.Context, sessClient pbs.SessionServiceClient, workerId, sessionId string) (*ConnInfo, int32, error) {
	resp, err := sessClient.AuthorizeConnection(ctx, &pbs.AuthorizeConnectionRequest{
		SessionId: sessionId,
		WorkerId:  workerId,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("error authorizing connection: %w", err)
	}

	return &ConnInfo{
		Id:     resp.ConnectionId,
		Status: resp.GetStatus(),
	}, resp.GetConnectionsLeft(), nil
}

// ConnectConnection is a helper worker function that sends connection
// connect request to the controller. It is called by the worker handler after a
// connection has been authorized.
func ConnectConnection(ctx context.Context, sessClient pbs.SessionServiceClient, req *pbs.ConnectConnectionRequest) (pbs.CONNECTIONSTATUS, error) {
	resp, err := sessClient.ConnectConnection(ctx, req)
	if err != nil {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, err
	}

	if resp.GetStatus() != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, fmt.Errorf("unexpected state returned: %v", resp.GetStatus().String())
	}

	return resp.GetStatus(), nil
}

func closeConnection(ctx context.Context, sessClient pbs.SessionServiceClient, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	const op = "session.closeConnection"
	resp, err := sessClient.CloseConnection(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.GetCloseResponseData()) != len(req.GetCloseRequestData()) {
		event.WriteError(ctx, op, errors.New("mismatched number of states returned on connection closed"), event.WithInfo("expected", len(req.GetCloseRequestData()), "got", len(resp.GetCloseResponseData())))
	}

	return resp, nil
}

// CloseConnections is a helper worker function that sends connection
// close requests to the controller, and sets close times within the
// worker. It is called during the worker status loop and on
// connection exit on the proxy.
//
// closeInfo is a map of connections mapped to their individual
// session.
func CloseConnections(ctx context.Context, sessClient pbs.SessionServiceClient, sessionInfo *sync.Map, closeInfo map[string]string) {
	const op = "session.CloseConnections"
	if closeInfo == nil {
		// This should not happen, but it's a no-op if it does. Just
		// return.
		return
	}

	// How we handle close info depends on whether or not we succeeded with
	// marking them closed on the controller.
	var sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData
	var err error

	// TODO: This, along with the status call to the controller, probably needs a
	// bit of formalization in terms of how we handle timeouts. For now, this
	// just ensures consistency with the same status call in that it times out
	// within an adequate period of time.
	closeConnCtx, closeConnCancel := context.WithTimeout(ctx, common.StatusTimeout)
	defer closeConnCancel()
	response, err := closeConnection(closeConnCtx, sessClient, makeCloseConnectionRequest(closeInfo))
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connections closed",
			"warning", "error contacting controller, connections will be closed only on worker",
			"session_and_connection_ids", fmt.Sprintf("%#v", closeInfo),
		))

		// Since we could not reach the controller, we have to make a "fake" response set.
		sessionCloseInfo, err = makeFakeSessionCloseInfo(closeInfo)
	} else {
		// Connection succeeded, so we can proceed with making the sessionCloseInfo
		// off of the response data.
		sessionCloseInfo, err = makeSessionCloseInfo(closeInfo, response)
	}

	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("serious error in processing return data from controller, aborting additional session/connection state modification"))
		return
	}

	// Mark connections as closed
	_, errs := setCloseTimeForResponse(sessionInfo, sessionCloseInfo)
	if len(errs) > 0 {
		for _, err := range errs {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connection closed in state"))
		}
	}
}

// makeCloseConnectionRequest creates a CloseConnectionRequest for
// use with closing connections.
//
// closeInfo is a map, indexed by connection ID, to the individual
// sessions IDs that those connections belong to. The values are
// ignored; the parameter is expected as such just for convenience of
// its caller.
func makeCloseConnectionRequest(closeInfo map[string]string) *pbs.CloseConnectionRequest {
	closeData := make([]*pbs.CloseConnectionRequestData, 0, len(closeInfo))
	for connId := range closeInfo {
		closeData = append(closeData, &pbs.CloseConnectionRequestData{
			ConnectionId: connId,
			Reason:       session.UnknownReason.String(),
		})
	}

	return &pbs.CloseConnectionRequest{
		CloseRequestData: closeData,
	}
}

// makeSessionCloseInfo takes the response from CloseConnections and
// our original closeInfo map and makes a map of slices, indexed by
// session ID, of all of the connection responses. This allows us to
// easily lock on session once for all connections in
// setCloseTimeForResponse.
func makeSessionCloseInfo(
	closeInfo map[string]string,
	response *pbs.CloseConnectionResponse,
) (map[string][]*pbs.CloseConnectionResponseData, error) {
	if closeInfo == nil {
		return nil, errMakeSessionCloseInfoNilCloseInfo
	}

	result := make(map[string][]*pbs.CloseConnectionResponseData)
	for _, v := range response.GetCloseResponseData() {
		result[closeInfo[v.GetConnectionId()]] = append(result[closeInfo[v.GetConnectionId()]], v)
	}

	return result, nil
}

// makeFakeSessionCloseInfo makes a "fake" makeFakeSessionCloseInfo, intended
// for use when we can't contact the controller.
func makeFakeSessionCloseInfo(
	closeInfo map[string]string,
) (map[string][]*pbs.CloseConnectionResponseData, error) {
	if closeInfo == nil {
		return nil, errMakeSessionCloseInfoNilCloseInfo
	}

	result := make(map[string][]*pbs.CloseConnectionResponseData)
	for connectionId, sessionId := range closeInfo {
		result[sessionId] = append(result[sessionId], &pbs.CloseConnectionResponseData{
			ConnectionId: connectionId,
			Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
		})
	}

	return result, nil
}

// setCloseTimeForResponse iterates a CloseConnectionResponse and
// sets the close time for any connection found to be closed to the
// current time.
//
// sessionCloseInfo can be derived from the closeInfo supplied to
// makeCloseConnectionRequest through reverseCloseInfo, which creates
// a session ID to connection ID mapping.
//
// A non-zero error count does not necessarily mean the operation
// failed, as some connections may have been marked as closed. The
// actual list of connection IDs closed is returned as the first
// return value.
func setCloseTimeForResponse(sessionInfo *sync.Map, sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData) ([]string, []error) {
	closedIds := make([]string, 0)
	var errors []error
	for sessionId, responses := range sessionCloseInfo {
		siRaw, ok := sessionInfo.Load(sessionId)
		if !ok {
			errors = append(errors, fmt.Errorf("could not find session ID %q in local state after closing connections", sessionId))
			continue
		}

		si := siRaw.(*Info)
		si.Lock()

		for _, response := range responses {
			ci, ok := si.ConnInfoMap[response.GetConnectionId()]
			if !ok {
				errors = append(errors,
					fmt.Errorf(
						"could not find connection ID %q for session ID %q in local state after closing connections",
						response.GetConnectionId(),
						sessionId,
					),
				)
				continue
			}

			ci.Status = response.GetStatus()
			if ci.Status == pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				ci.CloseTime = time.Now()
				closedIds = append(closedIds, ci.Id)
			}
		}

		si.Unlock()
	}

	return closedIds, errors
}
