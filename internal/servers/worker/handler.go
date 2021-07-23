package worker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/hashicorp/boundary/globals"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

type HandlerProperties struct {
	ListenerConfig *listenerutil.ListenerConfig
}

// Handler returns an http.Handler for the API. This can be used on
// its own to mount the Worker API within another web server.
func (w *Worker) handler(props HandlerProperties) http.Handler {
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	mux.Handle("/v1/proxy", w.handleProxy())

	genericWrappedHandler := w.wrapGenericHandler(mux, props)

	return genericWrappedHandler
}

func (w *Worker) handleProxy() http.HandlerFunc {
	const op = "worker.(Worker).handleProxy"
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS == nil {
			event.WriteError(ctx, op, errors.New("no request TLS information found"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		sessionId := r.TLS.ServerName

		clientIp, clientPort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfo(event.I{"msg": "unable to understand remote address", "remote_addr": r.RemoteAddr}))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		numPort, err := strconv.Atoi(clientPort)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to understand remote port"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		clientAddr := &net.TCPAddr{
			IP:   net.ParseIP(clientIp),
			Port: numPort,
		}

		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "received TLS connection"})

		siRaw, valid := w.sessionInfoMap.Load(sessionId)
		if !valid {
			event.WriteError(ctx, op, errors.New("session not found in info map"), event.WithInfo(event.I{"session_id": sessionId}))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		si := siRaw.(*sessionInfo)
		si.RLock()
		expiration := si.lookupSessionResponse.GetExpiration()
		tofuToken := si.lookupSessionResponse.GetTofuToken()
		version := si.lookupSessionResponse.GetVersion()
		endpoint := si.lookupSessionResponse.GetEndpoint()
		// userId := si.lookupSessionResponse.GetAuthorization()
		sessStatus := si.status
		si.RUnlock()

		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "found session in session info map"})

		opts := &websocket.AcceptOptions{
			Subprotocols: []string{globals.TcpProxyV1},
		}
		conn, err := websocket.Accept(wr, r, opts)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error during websocket upgrade"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Later calls will cause this to noop if they return a different status
		defer conn.Close(websocket.StatusNormalClosure, "done")

		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "websocket upgrade done"})

		connCtx, connCancel := context.WithDeadline(r.Context(), expiration.AsTime())
		defer connCancel()

		var handshake proxy.ClientHandshake
		if err := wspb.Read(connCtx, conn, &handshake); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error reading handshake from client"))
			conn.Close(websocket.StatusPolicyViolation, "invalid handshake received")
			return
		}
		if len(handshake.GetTofuToken()) < 20 {
			event.WriteError(ctx, op, errors.New("invalid tofu token"))
			conn.Close(websocket.StatusUnsupportedData, "invalid tofu token")
			return
		}

		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "proxy handshake finished"})

		if tofuToken != "" {
			if tofuToken != handshake.GetTofuToken() {
				event.WriteError(ctx, op, errors.New("WARNING: mismatched tofu token"), event.WithInfo(event.I{"session_id": sessionId}))
				conn.Close(websocket.StatusPolicyViolation, "tofu token not allowed")
				return
			}
		} else {
			if sessStatus != pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING {
				event.WriteError(ctx, op, err, event.WithInfoMsg("no tofu token but not in correct session state"))
				conn.Close(websocket.StatusInternalError, "refusing to activate session")
				return
			}
			if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_UNSPECIFIED {
				event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "activating session"})
				sessStatus, err = w.activateSession(r.Context(), sessionId, handshake.GetTofuToken(), version)
				if err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("unable to validate session"))
					conn.Close(websocket.StatusInternalError, "unable to activate session")
					return
				}
			}
		}

		if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL {
			event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "canceling session at client request"})
			_, err := w.cancelSession(r.Context(), sessionId)
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to cancel session"))
				conn.Close(websocket.StatusInternalError, "unable to cancel session")
				return
			}
			conn.Close(websocket.StatusNormalClosure, "session canceled")
			return
		}

		var ci *connInfo
		var connsLeft int32
		ci, connsLeft, err = w.authorizeConnection(r.Context(), sessionId)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to authorize connection"))
			conn.Close(websocket.StatusInternalError, "unable to authorize connection")
			return
		}

		defer func() {
			w.closeConnections(r.Context(), map[string]string{ci.id: si.id})
		}()

		si.Lock()
		ci.connCtx = connCtx
		ci.connCancel = connCancel
		si.connInfoMap[ci.id] = ci
		si.status = sessStatus
		connectionLimit := si.lookupSessionResponse.GetConnectionLimit()
		si.Unlock()

		event.WriteSysEvent(ctx, op, map[string]interface{}{"msg": "authorized connection", "connection_id": ci.id})

		handshakeResult := &proxy.HandshakeResult{
			Expiration:      expiration,
			ConnectionLimit: connectionLimit,
			ConnectionsLeft: connsLeft,
		}
		if err := wspb.Write(connCtx, conn, handshakeResult); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error sending handshake result to client"))
			conn.Close(websocket.StatusProtocolError, "unable to send handshake result")
			return
		}

		switch conn.Subprotocol() {
		case globals.TcpProxyV1:
			w.handleTcpProxyV1(connCtx, clientAddr, conn, si, ci.id, endpoint)
		default:
			conn.Close(websocket.StatusProtocolError, "unsupported-protocol")
			return
		}
	})
}

func (w *Worker) wrapGenericHandler(h http.Handler, props HandlerProperties) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Set the Cache-Control header for all responses returned
		wr.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(wr, r)
	})
}

/*
func WrapForwardedForHandler(h http.Handler, authorizedAddrs []*sockaddr.SockAddrMarshaler, rejectNotPresent, rejectNonAuthz bool, hopSkips int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers, headersOK := r.Header[textproto.CanonicalMIMEHeaderKey("X-Forwarded-For")]
		if !headersOK || len(headers) == 0 {
			if !rejectNotPresent {
				h.ServeHTTP(w, r)
				return
			}
			respondError(w, http.StatusBadRequest, fmt.Errorf("missing x-forwarded-for header and configured to reject when not present"))
			return
		}

		host, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If not rejecting treat it like we just don't have a valid
			// header because we can't do a comparison against an address we
			// can't understand
			if !rejectNotPresent {
				h.ServeHTTP(w, r)
				return
			}
			respondError(w, http.StatusBadRequest, errwrap.Wrapf("error parsing client hostport: {{err}}", err))
			return
		}

		addr, err := sockaddr.NewIPAddr(host)
		if err != nil {
			// We treat this the same as the case above
			if !rejectNotPresent {
				h.ServeHTTP(w, r)
				return
			}
			respondError(w, http.StatusBadRequest, errwrap.Wrapf("error parsing client address: {{err}}", err))
			return
		}

		var found bool
		for _, authz := range authorizedAddrs {
			if authz.Contains(addr) {
				found = true
				break
			}
		}
		if !found {
			// If we didn't find it and aren't configured to reject, simply
			// don't trust it
			if !rejectNonAuthz {
				h.ServeHTTP(w, r)
				return
			}
			respondError(w, http.StatusBadRequest, fmt.Errorf("client address not authorized for x-forwarded-for and configured to reject connection"))
			return
		}

		// At this point we have at least one value and it's authorized

		// Split comma separated ones, which are common. This brings it in line
		// to the multiple-header case.
		var acc []string
		for _, header := range headers {
			vals := strings.Split(header, ",")
			for _, v := range vals {
				acc = append(acc, strings.TrimSpace(v))
			}
		}

		indexToUse := len(acc) - 1 - hopSkips
		if indexToUse < 0 {
			// This is likely an error in either configuration or other
			// infrastructure. We could either deny the request, or we
			// could simply not trust the value. Denying the request is
			// "safer" since if this logic is configured at all there may
			// be an assumption it can always be trusted. Given that we can
			// deny accepting the request at all if it's not from an
			// authorized address, if we're at this point the address is
			// authorized (or we've turned off explicit rejection) and we
			// should assume that what comes in should be properly
			// formatted.
			respondError(w, http.StatusBadRequest, fmt.Errorf("malformed x-forwarded-for configuration or request, hops to skip (%d) would skip before earliest chain link (chain length %d)", hopSkips, len(headers)))
			return
		}

		r.RemoteAddr = net.JoinHostPort(acc[indexToUse], port)
		h.ServeHTTP(w, r)
		return
	})
}
*/
