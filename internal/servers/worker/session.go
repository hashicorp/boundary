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

const (
	validateSessionTimeout = 90 * time.Second
)

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

func (w *Worker) closeConnections(ctx context.Context, closeMap map[string]string) {
	w.logger.Trace("marking connections as closed", "session_and_connection_ids", fmt.Sprintf("%#v", closeMap))

	closeData := make([]*pbs.CloseConnectionRequestData, 0, len(closeMap))
	for connId := range closeMap {
		closeData = append(closeData, &pbs.CloseConnectionRequestData{
			ConnectionId: connId,
			Reason:       session.UnknownReason.String(),
		})
	}
	closeInfo := &pbs.CloseConnectionRequest{
		CloseRequestData: closeData,
	}

	// revMap is a reverse map to closeMap, that is, session ID to connection
	// IDs, for more efficient locking. How it gets populated depends on if we
	// can reach the controller.
	var revMap map[string][]*pbs.CloseConnectionResponseData
	var warnLocal bool
	connStatus, err := w.closeConnection(ctx, closeInfo)
	if err != nil {
		w.logger.Error("error marking connections closed", "error", err)
		warnLocal = true
		// Since we can't reach the controller, we populate this "manually",
		// marking every connection closed. This is to cover edge cases such as if
		// we can reach the controller on the next heartbeat before we reap the
		// connectionless session.
		revMap := make(map[string][]*pbs.CloseConnectionResponseData)
		for connectionId, sessionId := range closeMap {
			revMap[sessionId] = append(revMap[sessionId], &pbs.CloseConnectionResponseData{
				ConnectionId: connectionId,
				Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
			})
		}
	} else {
		// Normal operation: connection to the controller was successful. Populate
		// revMap from the response.
		revMap = make(map[string][]*pbs.CloseConnectionResponseData)
		for _, v := range connStatus.GetCloseResponseData() {
			revMap[closeMap[v.GetConnectionId()]] = append(revMap[closeMap[v.GetConnectionId()]], v)
		}
	}

	closedIds := make([]string, 0, len(connStatus.GetCloseResponseData()))
	for k, v := range revMap {
		siRaw, ok := w.sessionInfoMap.Load(k)
		if !ok {
			w.logger.Warn("could not find session ID in info map after closing connections", "session_id", k)
			continue
		}
		si := siRaw.(*sessionInfo)
		si.Lock()
		for _, connResult := range v {
			ci := si.connInfoMap[connResult.GetConnectionId()]
			ci.status = connResult.GetStatus()
			if ci.status == pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				ci.closeTime = time.Now()
				closedIds = append(closedIds, ci.id)
			}
		}
		si.Unlock()
	}

	if warnLocal {
		w.logger.Warn("connections marked closed on worker only, could not reach controllers", "connection_ids", closedIds)
	} else {
		w.logger.Trace("connections successfully marked closed", "connection_ids", closedIds)
	}
}
