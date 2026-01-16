// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/session"
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

	// The number of bytes uploaded from the client.
	BytesUp func() int64
	// The number of bytes downloaded to the client.
	BytesDown func() int64

	// The time the controller has successfully reported that this connection is
	// closed.
	CloseTime time.Time
}

// ConnectionCloseData encapsulates the data we need to send via CloseConnection
// RPC to the controller.
type ConnectionCloseData struct {
	SessionId string
	BytesUp   int64
	BytesDown int64
}

// Session is the local representation of a session.  After initial loading
// the only values that will change will be the status (readable from
// GetStatus()) and the Connections (GetLocalConnections()).
type Session interface {
	// ApplyLocalConnectionStatus set's a connection's status to the one provided.
	// If there is no connection with the provided id, an error is returned.
	ApplyLocalConnectionStatus(connId string, status pbs.CONNECTIONSTATUS) error

	// ApplyLocalStatus updates the given session with the status provided by
	// the SessionJobInfo.  It returns an error if any of the connections
	// in the SessionJobInfo are not present, however, it still applies the
	// status change to the session and the connections which are present.
	ApplyLocalStatus(st pbs.SESSIONSTATUS)
	GetStatus() pbs.SESSIONSTATUS
	// GetLocalConnections returns the connections this session is handling.
	GetLocalConnections() map[string]ConnInfo
	GetTofuToken() string
	GetConnectionLimit() int32
	GetEndpoint() string
	GetHostKeys() ([]crypto.Signer, error)
	GetCredentials() []*pbs.Credential
	GetExpiration() time.Time
	GetCertificate() *x509.Certificate
	GetPrivateKey() []byte
	GetId() string

	// CancelOpenLocalConnections closes the local connections in this session
	//based on the connection's state by calling the connections context cancel
	// function.
	//
	// The returned slice are connection ids that were closed.
	CancelOpenLocalConnections() []string

	// CancelAllLocalConnections close connections regardless of connection's state
	// by calling the connection context's CancelFunc.
	//
	// The returned slice is the connection ids which were closed.
	CancelAllLocalConnections() []string

	// RequestCancel sends session cancellation request to the controller.  If there is no
	// error the local session's status is updated with the result of the cancel
	// request
	RequestCancel(ctx context.Context) error

	// RequestActivate sends session activation request to the controller.  The Session's
	// status is then updated with the result of the call.  After a successful
	// call to RequestActivate, subsequent calls will fail.
	RequestActivate(ctx context.Context, tofu string) error

	// ApplyConnectionCounterCallbacks sets a connection's bytes up and bytes
	// down callbacks to the provided functions. Both functions must be safe for
	// concurrent use. If there is no connection with the provided id, an error
	// is returned.
	ApplyConnectionCounterCallbacks(connId string, bytesUp func() int64, bytesDown func() int64) error

	// RequestAuthorizeConnection sends an AuthorizeConnection request to
	// the controller.
	// It is called by the worker handler after a connection has been received by
	// the worker, and the session has been validated.
	// The passed in context.CancelFunc is used to terminate any ongoing local proxy
	// connections.
	// The connection status is then viewable in this session's GetLocalConnections() call.
	RequestAuthorizeConnection(ctx context.Context, workerId string, connCancel context.CancelFunc) (*pbs.AuthorizeConnectionResponse, int32, error)

	// RequestConnectConnection sends a RequestConnectConnection request to the controller. It
	// should only be called by the worker handler after a connection has been
	// authorized.  The local connection's status is updated with the result of the
	// call.
	RequestConnectConnection(ctx context.Context, info *pbs.ConnectConnectionRequest) error
}

type sess struct {
	lock        sync.RWMutex
	client      pbs.SessionServiceClient
	connInfoMap map[string]*ConnInfo
	resp        *pbs.LookupSessionResponse
	status      pbs.SESSIONSTATUS
	cert        *x509.Certificate
	sessionId   string
	tofuToken   string
}

func newSess(client pbs.SessionServiceClient, resp *pbs.LookupSessionResponse) (*sess, error) {
	switch {
	case isNil(client):
		return nil, errors.New("SessionServiceClient is nil")
	case resp.GetExpiration().AsTime().Before(time.Now()):
		return nil, fmt.Errorf("session is expired")
	}

	parsedCert, err := x509.ParseCertificate(resp.GetAuthorization().GetCertificate())
	if err != nil {
		return nil, fmt.Errorf("error parsing session certificate: %w", err)
	}

	s := &sess{
		client:      client,
		connInfoMap: make(map[string]*ConnInfo),
		resp:        resp,
		status:      resp.GetStatus(),
		cert:        parsedCert,
		sessionId:   resp.GetAuthorization().GetSessionId(),
	}
	return s, nil
}

// ApplyLocalConnectionStatus Satisfies the Session interface
func (s *sess) ApplyLocalConnectionStatus(connId string, status pbs.CONNECTIONSTATUS) error {
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

func (s *sess) ApplySessionUpdate(r *pbs.LookupSessionResponse) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.resp = r
	s.status = r.Status
}

func (s *sess) ApplyLocalStatus(st pbs.SESSIONSTATUS) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.status = st
}

func (s *sess) ApplyLocalTofuToken(tt string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.tofuToken = tt
}

func (s *sess) GetLocalConnections() map[string]ConnInfo {
	s.lock.RLock()
	defer s.lock.RUnlock()
	res := make(map[string]ConnInfo, len(s.connInfoMap))
	// Returning the s.connInfoMap directly wouldn't be thread safe.
	for k, v := range s.connInfoMap {
		res[k] = ConnInfo{
			Id:        v.Id,
			Status:    v.Status,
			CloseTime: v.CloseTime,
			BytesUp:   v.BytesUp,
			BytesDown: v.BytesDown,
		}
	}
	return res
}

// Return local tofu token, if available; otherwise return the tofu token from the resp
func (s *sess) GetTofuToken() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if len(s.tofuToken) > 0 {
		return s.tofuToken
	}
	if s.resp != nil {
		return s.resp.GetTofuToken()
	}
	return ""
}

func (s *sess) GetConnectionLimit() int32 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.resp.GetConnectionLimit()
}

func (s *sess) GetEndpoint() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.resp.GetEndpoint()
}

func (s *sess) GetHostKeys() ([]crypto.Signer, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	pkcs8Keys := s.resp.GetPkcs8HostKeys()

	var hostKeys []crypto.Signer
	for _, hostKey := range pkcs8Keys {
		p, err := x509.ParsePKCS8PrivateKey(hostKey)
		if err != nil {
			return nil, errors.New("error parsing host keys")
		}

		hostKey, ok := p.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported host key %T", p)
		}
		hostKeys = append(hostKeys, hostKey)

	}
	return hostKeys, nil
}

func (s *sess) GetCredentials() []*pbs.Credential {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.resp.GetCredentials()
}

func (s *sess) GetStatus() pbs.SESSIONSTATUS {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.status
}

func (s *sess) GetExpiration() time.Time {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.resp.GetExpiration().AsTime()
}

func (s *sess) GetCertificate() *x509.Certificate {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cert
}

func (s *sess) GetPrivateKey() []byte {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.resp.GetAuthorization().GetPrivateKey()
}

func (s *sess) GetId() string {
	return s.sessionId
}

func (s *sess) RequestCancel(ctx context.Context) error {
	st, err := cancel(ctx, s.client, s.GetId())
	if err != nil {
		return err
	}
	s.ApplyLocalStatus(st)
	return nil
}

func (s *sess) RequestActivate(ctx context.Context, tofu string) error {
	st, err := activate(ctx, s.client, s.GetId(), tofu, s.resp.GetVersion())
	if err != nil {
		return err
	}
	s.ApplyLocalTofuToken(tofu)
	s.ApplyLocalStatus(st)
	return nil
}

func (s *sess) RequestAuthorizeConnection(ctx context.Context, workerId string, connCancel context.CancelFunc) (*pbs.AuthorizeConnectionResponse, int32, error) {
	switch {
	case connCancel == nil:
		return nil, 0, errors.New("the provided context.CancelFunc was nil")
	case workerId == "":
		return nil, 0, errors.New("worker id is empty")
	}

	resp, err := s.client.AuthorizeConnection(ctx, &pbs.AuthorizeConnectionRequest{
		SessionId: s.GetId(),
		WorkerId:  workerId,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("error authorizing connection: %w", err)
	}
	ci := &ConnInfo{
		Id:                resp.GetConnectionId(),
		Status:            resp.GetStatus(),
		connCtxCancelFunc: connCancel,
	}

	// Install safe callbacks before connection has been established. These
	// should be replaced when `ApplyConnectionCounterCallbacks` gets called on
	// the `sess` object.
	ci.BytesUp = func() int64 { return 0 }
	ci.BytesDown = func() int64 { return 0 }

	s.lock.Lock()
	defer s.lock.Unlock()
	s.connInfoMap[ci.Id] = ci
	return resp, resp.GetConnectionsLeft(), err
}

func (s *sess) RequestConnectConnection(ctx context.Context, info *pbs.ConnectConnectionRequest) error {
	st, err := connectConnection(ctx, s.client, info)
	if err != nil {
		return err
	}
	if err := s.ApplyLocalConnectionStatus(info.GetConnectionId(), st); err != nil {
		return fmt.Errorf("error applying local connection status: %w", err)
	}
	return nil
}

// CancelOpenLocalConnections closes the local connections in this session
// based on the connection's state by calling the connections context cancel
// function.
//
// The returned slice are connection ids that were closed.
func (s *sess) CancelOpenLocalConnections() []string {
	s.lock.RLock()
	defer s.lock.RUnlock()
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
func (s *sess) CancelAllLocalConnections() []string {
	s.lock.RLock()
	defer s.lock.RUnlock()
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

// ApplyConnectionCounterCallbacks sets a connection's bytes up and bytes
// down callbacks to the provided functions. Both functions must be safe for
// concurrent use. If there is no connection with the provided id, an error
// is returned.
func (s *sess) ApplyConnectionCounterCallbacks(connId string, bytesUp func() int64, bytesDown func() int64) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	ci, ok := s.connInfoMap[connId]
	if !ok {
		return fmt.Errorf("failed to find connection info for connection id %q", connId)
	}
	ci.BytesUp = bytesUp
	ci.BytesDown = bytesDown
	return nil
}

// activate is a helper worker function that sends session activation request to the
// controller.
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

// cancel is a helper worker function that sends session cancellation request to the
// controller.
func cancel(ctx context.Context, sessClient pbs.SessionServiceClient, sessionId string) (pbs.SESSIONSTATUS, error) {
	resp, err := sessClient.CancelSession(ctx, &pbs.CancelSessionRequest{
		SessionId: sessionId,
	})
	if err != nil {
		return pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED, fmt.Errorf("error canceling session: %w", err)
	}
	return resp.GetStatus(), nil
}

// connectConnection is a helper worker function that sends connection
// connect request to the controller. It is called by the worker handler after a
// connection has been authorized.
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
// called during the worker session info loop and on connection exit on the proxy.
//
// The boolean indicates whether the function was successful, e.g. had any
// errors. Individual events will be sent for the errors if there are any.
//
// closeInfo is a map of connection id to connection metadata.
func closeConnections(ctx context.Context, sessClient pbs.SessionServiceClient, sManager Manager, closeInfo map[string]*ConnectionCloseData) bool {
	const op = "session.closeConnections"
	if len(closeInfo) == 0 {
		// This should not happen, but it's a no-op if it does. Just
		// return.
		return false
	}

	// How we handle close info depends on whether or not we succeeded with
	// marking them closed on the controller.
	var sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData
	var err error

	// TODO: This, along with the session info call to the controller, probably needs a
	// bit of formalization in terms of how we handle timeouts. For now, this
	// just ensures consistency with the same session info call in that it times out
	// within an adequate period of time.
	closeConnCtx, closeConnCancel := context.WithTimeout(ctx, time.Duration(CloseCallTimeout.Load()))
	defer closeConnCancel()
	response, err := closeConnection(closeConnCtx, sessClient, makeCloseConnectionRequest(closeInfo))
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error marking connections closed",
			"warning", "error contacting controller, connections will be closed only on worker",
			"session_and_connection_ids", fmt.Sprintf("%#v", closeInfo),
			"timeout", time.Duration(CloseCallTimeout.Load()).String(),
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
	_, errs := setCloseTimeForResponse(sManager, sessionCloseInfo)
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
func makeCloseConnectionRequest(closeInfo map[string]*ConnectionCloseData) *pbs.CloseConnectionRequest {
	closeData := make([]*pbs.CloseConnectionRequestData, 0, len(closeInfo))
	for connId, data := range closeInfo {
		closeData = append(closeData, &pbs.CloseConnectionRequestData{
			ConnectionId: connId,
			Reason:       session.UnknownReason.String(),
			BytesUp:      data.BytesUp,
			BytesDown:    data.BytesDown,
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
	closeInfo map[string]*ConnectionCloseData,
	response *pbs.CloseConnectionResponse,
) (map[string][]*pbs.CloseConnectionResponseData, error) {
	if closeInfo == nil {
		return nil, errMakeSessionCloseInfoNilCloseInfo
	}

	result := make(map[string][]*pbs.CloseConnectionResponseData)
	for _, v := range response.GetCloseResponseData() {
		sessionId := closeInfo[v.GetConnectionId()].SessionId
		result[sessionId] = append(result[sessionId], v)
	}

	return result, nil
}

// makeFakeSessionCloseInfo makes a "fake" makeFakeSessionCloseInfo, intended
// for use when we can't contact the controller.
func makeFakeSessionCloseInfo(
	closeInfo map[string]*ConnectionCloseData,
) (map[string][]*pbs.CloseConnectionResponseData, error) {
	if closeInfo == nil {
		return nil, errMakeSessionCloseInfoNilCloseInfo
	}

	result := make(map[string][]*pbs.CloseConnectionResponseData)
	for connectionId, closeData := range closeInfo {
		sessionId := closeData.SessionId
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
func setCloseTimeForResponse(sManager Manager, sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData) ([]string, []error) {
	closedIds := make([]string, 0)
	var result []error
	for sessionId, responses := range sessionCloseInfo {
		si := sManager.Get(sessionId)
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
