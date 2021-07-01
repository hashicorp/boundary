package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/session"
)

const validateSessionTimeout = 90 * time.Second

var errMakeSessionCloseInfoNilCloseInfo = errors.New("nil closeInfo supplied to makeSessionCloseInfo, this is a bug, please report it")

type connInfo struct {
	id         string
	connCtx    context.Context
	connCancel context.CancelFunc
	status     pbs.CONNECTIONSTATUS
	closeTime  time.Time
}

type sessionInfo struct {
	sync.RWMutex
	id                    string
	sessionTls            *tls.Config
	status                pbs.SESSIONSTATUS
	lookupSessionResponse *pbs.LookupSessionResponse
	connInfoMap           map[string]*connInfo
}

func (w *Worker) getSessionTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	var sessionId string
	switch {
	case strings.HasPrefix(hello.ServerName, "s_"):
		w.logger.Trace("got valid session in SNI", "session_id", hello.ServerName)
		sessionId = hello.ServerName
	default:
		w.logger.Trace("invalid session in SNI", "session_id", hello.ServerName)
		return nil, fmt.Errorf("could not find session ID in SNI")
	}

	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		w.logger.Trace("could not get a controller client", "session_id", sessionId)
		return nil, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		w.logger.Trace("could not cast controller client to the real thing", "session_id", sessionId)
		return nil, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		w.logger.Trace("controller client is nil", "session_id", sessionId)
		return nil, errors.New("controller client is nil")
	}

	timeoutContext, cancel := context.WithTimeout(w.baseContext, validateSessionTimeout)
	defer cancel()

	w.logger.Trace("looking up session", "session_id", sessionId)
	resp, err := conn.LookupSession(timeoutContext, &pbs.LookupSessionRequest{
		ServerId:  w.conf.RawConfig.Worker.Name,
		SessionId: sessionId,
	})
	if err != nil {
		return nil, fmt.Errorf("error validating session: %w", err)
	}

	if resp.GetExpiration().AsTime().Before(time.Now()) {
		return nil, fmt.Errorf("session is expired")
	}

	parsedCert, err := x509.ParseCertificate(resp.GetAuthorization().Certificate)
	if err != nil {
		return nil, fmt.Errorf("error parsing session certificate: %w", err)
	}

	if len(parsedCert.DNSNames) != 1 {
		return nil, fmt.Errorf("invalid length of DNS names (%d) in parsed certificate", len(parsedCert.DNSNames))
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{resp.GetAuthorization().Certificate},
				PrivateKey:  ed25519.PrivateKey(resp.GetAuthorization().PrivateKey),
				Leaf:        parsedCert,
			},
		},
		ServerName: parsedCert.DNSNames[0],
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
		MinVersion: tls.VersionTLS13,
	}

	si := &sessionInfo{
		id:                    resp.GetAuthorization().GetSessionId(),
		sessionTls:            tlsConf,
		lookupSessionResponse: resp,
		status:                resp.GetStatus(),
		connInfoMap:           make(map[string]*connInfo),
	}
	// TODO: Periodicially clean this up. We can't rely on things in here but
	// not in cancellation because they could be on the way to being
	// established. However, since cert lifetimes are short, we can simply range
	// through and remove values that are expired.
	actualSiRaw, loaded := w.sessionInfoMap.LoadOrStore(sessionId, si)
	if loaded {
		// Update the response to the latest
		actualSi := actualSiRaw.(*sessionInfo)
		actualSi.Lock()
		actualSi.lookupSessionResponse = resp
		actualSi.Unlock()
	}

	w.logger.Trace("returning TLS configuration", "session_id", sessionId)
	return tlsConf, nil
}

func (w *Worker) activateSession(ctx context.Context, sessionId, tofuToken string, version uint32) (pbs.SESSIONSTATUS, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("controller client is nil")
	}

	resp, err := conn.ActivateSession(ctx, &pbs.ActivateSessionRequest{
		SessionId: sessionId,
		TofuToken: tofuToken,
		Version:   version,
		WorkerId:  w.conf.RawConfig.Worker.Name,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error activating session: %w", err)
	}
	return resp.GetStatus(), nil
}

func (w *Worker) cancelSession(ctx context.Context, sessionId string) (pbs.SESSIONSTATUS, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, errors.New("controller client is nil")
	}

	resp, err := conn.CancelSession(ctx, &pbs.CancelSessionRequest{
		SessionId: sessionId,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error canceling session: %w", err)
	}
	return resp.GetStatus(), nil
}

func (w *Worker) authorizeConnection(ctx context.Context, sessionId string) (*connInfo, int32, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return nil, 0, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return nil, 0, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return nil, 0, errors.New("controller client is nil")
	}

	resp, err := conn.AuthorizeConnection(ctx, &pbs.AuthorizeConnectionRequest{
		SessionId: sessionId,
		WorkerId:  w.conf.RawConfig.Worker.Name,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("error authorizing connection: %w", err)
	}

	return &connInfo{
		id:     resp.ConnectionId,
		status: resp.GetStatus(),
	}, resp.GetConnectionsLeft(), nil
}

func (w *Worker) connectConnection(ctx context.Context, req *pbs.ConnectConnectionRequest) (pbs.CONNECTIONSTATUS, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, errors.New("controller client is nil")
	}

	resp, err := conn.ConnectConnection(ctx, req)
	if err != nil {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, err
	}

	if resp.GetStatus() != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED {
		return pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED, fmt.Errorf("unexpected state returned: %v", resp.GetStatus().String())
	}

	return resp.GetStatus(), nil
}

func (w *Worker) closeConnection(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return nil, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return nil, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return nil, errors.New("controller client is nil")
	}

	resp, err := conn.CloseConnection(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.GetCloseResponseData()) != len(req.GetCloseRequestData()) {
		w.logger.Warn("mismatched number of states returned on connection closed", "expected", len(req.GetCloseRequestData()), "got", len(resp.GetCloseResponseData()))
	}

	return resp, nil
}

// closeConnections is a helper worker function that sends connection
// close requests to the controller, and sets close times within the
// worker. It is called during the worker status loop and on
// connection exit on the proxy.
//
// closeInfo is a map of connections mapped to their individual
// session.
func (w *Worker) closeConnections(ctx context.Context, closeInfo map[string]string) {
	if closeInfo == nil {
		// This should not happen, but it's a no-op if it does. Just
		// return.
		return
	}

	w.logger.Trace("marking connections as closed", "session_and_connection_ids", fmt.Sprintf("%#v", closeInfo))

	// How we handle close info depends on whether or not we succeeded with
	// marking them closed on the controller.
	var sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData
	var err error

	// TODO: This, along with the status call to the controller, probably needs a
	// bit of formalization in terms of how we handle timeouts. For now, this
	// just ensures consistency with the same status call in that it times out
	// within an adequate period of time.
	closeConnCtx, closeConnCancel := context.WithTimeout(ctx, statusTimeout)
	defer closeConnCancel()
	response, err := w.closeConnection(closeConnCtx, w.makeCloseConnectionRequest(closeInfo))
	if err != nil {
		w.logger.Error("error marking connections closed", "error", err)
		w.logger.Warn(
			"error contacting controller, connections will be closed only on worker",
			"session_and_connection_ids", fmt.Sprintf("%#v", closeInfo),
		)

		// Since we could not reach the controller, we have to make a "fake" response set.
		sessionCloseInfo, err = w.makeFakeSessionCloseInfo(closeInfo)
	} else {
		// Connection succeeded, so we can proceed with making the sessionCloseInfo
		// off of the response data.
		sessionCloseInfo, err = w.makeSessionCloseInfo(closeInfo, response)
	}

	if err != nil {
		w.logger.Error(err.Error())
		w.logger.Error("serious error in processing return data from controller, aborting additional session/connection state modification")
		return
	}

	// Mark connections as closed
	closedIds, errs := w.setCloseTimeForResponse(sessionCloseInfo)
	if len(errs) > 0 {
		for _, err := range errs {
			w.logger.Error("error marking connection closed in state", "err", err)
		}
	}

	w.logger.Trace("connections successfully marked closed", "connection_ids", closedIds)
}

// makeCloseConnectionRequest creates a CloseConnectionRequest for
// use with closing connections.
//
// closeInfo is a map, indexed by connection ID, to the individual
// sessions IDs that those connections belong to. The values are
// ignored; the parameter is expected as such just for convenience of
// its caller.
func (w *Worker) makeCloseConnectionRequest(closeInfo map[string]string) *pbs.CloseConnectionRequest {
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
func (w *Worker) makeSessionCloseInfo(
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
func (w *Worker) makeFakeSessionCloseInfo(
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
func (w *Worker) setCloseTimeForResponse(sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData) ([]string, []error) {
	closedIds := make([]string, 0)
	var errors []error
	for sessionId, responses := range sessionCloseInfo {
		siRaw, ok := w.sessionInfoMap.Load(sessionId)
		if !ok {
			errors = append(errors, fmt.Errorf("could not find session ID %q in local state after closing connections", sessionId))
			continue
		}

		si := siRaw.(*sessionInfo)
		si.Lock()

		for _, response := range responses {
			ci, ok := si.connInfoMap[response.GetConnectionId()]
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

			ci.status = response.GetStatus()
			if ci.status == pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				ci.closeTime = time.Now()
				closedIds = append(closedIds, ci.id)
			}
		}

		si.Unlock()
	}

	return closedIds, errors
}
