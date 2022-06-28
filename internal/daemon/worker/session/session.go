package session

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/session"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// ValidateSessionTimeout is the duration of the timeout when the worker queries the
// controller for the sessionId for which the connection is being requested.
const ValidateSessionTimeout = 90 * time.Second

var errMakeSessionCloseInfoNilCloseInfo = errors.New("nil closeInfo supplied to makeSessionCloseInfo, this is a bug, please report it")

// ConnInfo defines the information about a connection attached to a session
type ConnInfo struct {
	Id     string
	Status pbs.CONNECTIONSTATUS

	// The context.CancelFunc for the proxy connection.  Calling this function
	// closes the proxy connection.
	connCtxCancelFunc context.CancelFunc

	// The time the controller has successfully reported that this connection is
	// closed.
	CloseTime time.Time
}

// Session is the local representation of a session.  After initial loading
// the only values that will change will be the status (readable from
// GetStatus()) and the Connections (GetLocalConnections()).
type Session struct {
	lock        sync.RWMutex
	client      pbs.SessionServiceClient
	connInfoMap map[string]*ConnInfo
	resp        *pbs.LookupSessionResponse
	status      pbs.SESSIONSTATUS
	cert        *x509.Certificate
}

func newSess(client pbs.SessionServiceClient, resp *pbs.LookupSessionResponse) (*Session, error) {
	if resp.GetExpiration().AsTime().Before(time.Now()) {
		return nil, fmt.Errorf("session is expired")
	}

	parsedCert, err := x509.ParseCertificate(resp.GetAuthorization().GetCertificate())
	if err != nil {
		return nil, fmt.Errorf("error parsing session certificate: %w", err)
	}

	s := &Session{
		client:      client,
		connInfoMap: make(map[string]*ConnInfo),
		resp:        resp,
		status:      resp.GetStatus(),
		cert:        parsedCert,
	}
	return s, nil
}

// ApplyLocalConnectionStatus set's a connection's status to the one provided.
// If there is no connection with the provided id, an error is returned.
func (s *Session) ApplyLocalConnectionStatus(connId string, status pbs.CONNECTIONSTATUS) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	// Update connection status if there are any connections in
	// the request.
	connInfo, ok := s.connInfoMap[connId]
	if !ok {
		return fmt.Errorf("could not find connection ID %q for session ID %q in local state",
			connId,
			s.GetId())
	}

	connInfo.Status = status
	if connInfo.Status == pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
		connInfo.CloseTime = time.Now()
	}
	return nil
}

// ApplyLocalStatus updates the given session with the status provided by
// the SessionJobInfo.  It returns an error if any of the connections
// in the SessionJobInfo are not present, however, it still applies the
// status change to the session and the connections which are present.
func (s *Session) ApplyLocalStatus(st pbs.SESSIONSTATUS) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.status = st
}

// GetLocalConnections returns the connections this session is handling.
func (s *Session) GetLocalConnections() map[string]ConnInfo {
	s.lock.RLock()
	defer s.lock.RUnlock()
	res := make(map[string]ConnInfo, len(s.connInfoMap))
	// Returning the s.connInfoMap directly wouldn't be thread safe.
	for k, v := range s.connInfoMap {
		res[k] = ConnInfo{
			Id:        v.Id,
			Status:    v.Status,
			CloseTime: v.CloseTime,
		}
	}
	return res
}

func (s *Session) GetTofuToken() string {
	return s.resp.GetTofuToken()
}

func (s *Session) GetConnectionLimit() int32 {
	return s.resp.GetConnectionLimit()
}

func (s *Session) GetEndpoint() string {
	return s.resp.GetEndpoint()
}

func (s *Session) GetCredentials() []*pbs.Credential {
	return s.resp.GetCredentials()
}

func (s *Session) GetStatus() pbs.SESSIONSTATUS {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.status
}

func (s *Session) GetExpiration() time.Time {
	return s.resp.GetExpiration().AsTime()
}

func (s *Session) GetCertificate() *x509.Certificate {
	return s.cert
}

func (s *Session) GetPrivateKey() []byte {
	return s.resp.GetAuthorization().GetPrivateKey()
}

func (s *Session) GetId() string {
	return s.resp.GetAuthorization().GetSessionId()
}

// RequestCancel sends session cancellation request to the controller.  If there is no
// error the local session's status is updated with the result of the cancel
// request
func (s *Session) RequestCancel(ctx context.Context) error {
	st, err := cancel(ctx, s.client, s.GetId())
	if err != nil {
		return err
	}
	s.ApplyLocalStatus(st)
	return nil
}

// RequestActivate Sends session activation request to the controller.  The Session's
// status is then updated with the result of the call.  After a successful
// call to RequestActivate, subsequent calls will fail.
func (s *Session) RequestActivate(ctx context.Context, tofu string) error {
	st, err := activate(ctx, s.client, s.GetId(), tofu, s.resp.GetVersion())
	if err != nil {
		return err
	}
	s.ApplyLocalStatus(st)
	return nil
}

// RequestAuthorizeConnection sends an AuthorizeConnection request to
// the controller.
// It is called by the worker handler after a connection has been received by
// the worker, and the session has been validated.
// The passed in context.CancelFunc is used to terminate any ongoing local proxy
// connections.
// The connection status is then viewable in this session's GetLocalConnections() call.
func (s *Session) RequestAuthorizeConnection(ctx context.Context, workerId string, connCancel context.CancelFunc) (ConnInfo, int32, error) {
	ci, connsLeft, err := authorizeConnection(ctx, s.client, workerId, s.GetId())
	if err != nil {
		return ConnInfo{}, connsLeft, err
	}
	ci.connCtxCancelFunc = connCancel
	s.lock.Lock()
	defer s.lock.Unlock()
	s.connInfoMap[ci.Id] = ci
	return ConnInfo{
		Id:                ci.Id,
		connCtxCancelFunc: connCancel,
		Status:            ci.Status,
		CloseTime:         ci.CloseTime,
	}, connsLeft, err
}

// RequestConnectConnection sends a RequestConnectConnection request to the controller. It
// should only be called by the worker handler after a connection has been
// authorized.  The local connection's status is updated with the result of the
// call.
func (s *Session) RequestConnectConnection(ctx context.Context, info *pbs.ConnectConnectionRequest) error {
	st, err := connectConnection(ctx, s.client, info)
	if err != nil {
		return err
	}
	s.ApplyLocalConnectionStatus(info.GetConnectionId(), st)
	return nil
}

// CancelOpenLocalConnections closes the local connections in this session
//based on the connection's state by calling the connections context cancel
// function.
//
// The returned slice are connection ids that were closed.
func (s *Session) CancelOpenLocalConnections() []string {
	var closedIds []string
	for k, v := range s.connInfoMap {
		if v.Status != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
			continue
		}
		v.connCtxCancelFunc()

		// CloseTime is set when the controller has reported that the connection
		// is closed.  The worker should only request a connection be marked
		// closed after it has already been cancelled.
		if v.CloseTime.IsZero() {
			closedIds = append(closedIds, k)
		}
	}

	return closedIds
}

// CancelAllLocalConnections close connections regardless of connection's state
// by calling the connection context's CancelFunc.
//
// The returned slice is the connection ids which were closed.
func (s *Session) CancelAllLocalConnections() []string {
	var closedIds []string
	for k, v := range s.connInfoMap {
		v.connCtxCancelFunc()

		// CloseTime is set when the controller has reported that the connection
		// is closed.  The worker should only request a connection be marked
		// closed after it has already been cancelled.
		if v.CloseTime.IsZero() {
			closedIds = append(closedIds, k)
		}
	}

	return closedIds
}

func activate(ctx context.Context, sessClient pbs.SessionServiceClient, sessionId, tofuToken string, version uint32) (pbs.SESSIONSTATUS, error) {
	resp, err := sessClient.ActivateSession(ctx, &pbs.ActivateSessionRequest{
		SessionId: sessionId,
		TofuToken: tofuToken,
		Version:   version,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error activating session: %w", err)
	}
	return resp.GetStatus(), nil
}

func cancel(ctx context.Context, sessClient pbs.SessionServiceClient, sessionId string) (pbs.SESSIONSTATUS, error) {
	resp, err := sessClient.CancelSession(ctx, &pbs.CancelSessionRequest{
		SessionId: sessionId,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error canceling session: %w", err)
	}
	return resp.GetStatus(), nil
}

func authorizeConnection(ctx context.Context, sessClient pbs.SessionServiceClient, workerId, sessionId string) (*ConnInfo, int32, error) {
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

func connectConnection(ctx context.Context, sessClient pbs.SessionServiceClient, req *pbs.ConnectConnectionRequest) (pbs.CONNECTIONSTATUS, error) {
	resp, err := sessClient.ConnectConnection(ctx, req)
	if err != nil {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, err
	}

	if resp.GetStatus() != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, fmt.Errorf("unexpected state returned: %v", resp.GetStatus().String())
	}

	return resp.GetStatus(), nil
}

// TODO: Move these to manager.go.  This is kept here for now simply to make it easier to see the diff.

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

// closeConnections is a helper worker function that sends connection close
// requests to the controller, and sets close times within the worker. It is
// called during the worker status loop and on connection exit on the proxy.
//
// The boolean indicates whether the function was successful, e.g. had any
// errors. Individual events will be sent for the errors if there are any.
//
// closeInfo is a map of connections mapped to their individual session.
func closeConnections(ctx context.Context, sessClient pbs.SessionServiceClient, sCache *Manager, closeInfo map[string]string) bool {
	const op = "session.closeConnections"
	if closeInfo == nil {
		// This should not happen, but it's a no-op if it does. Just
		// return.
		return false
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
		return false
	}

	// Mark connections as closed
	_, errs := setCloseTimeForResponse(sCache, sessionCloseInfo)
	if len(errs) > 0 {
		for _, err := range errs {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connection closed in state"))
		}
		return false
	}

	return true
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

// makeSessionCloseInfo takes the response from closeConnections and
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
func setCloseTimeForResponse(sCache *Manager, sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData) ([]string, []error) {
	closedIds := make([]string, 0)
	var result []error
	for sessionId, responses := range sessionCloseInfo {
		si := sCache.Get(sessionId)
		if si == nil {
			result = append(result, fmt.Errorf("could not find session ID %q in local state after closing connections", sessionId))
			continue
		}
		connStatus := make(map[string]pbs.CONNECTIONSTATUS, len(responses))
		for _, response := range responses {
			if err := si.ApplyLocalConnectionStatus(response.GetConnectionId(), response.GetStatus()); err != nil {
				result = append(result, err)
				continue
			}
			connStatus[response.GetConnectionId()] = response.GetStatus()
			if response.GetStatus() == pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				closedIds = append(closedIds, response.GetConnectionId())
			}
		}
	}

	return closedIds, result
}
