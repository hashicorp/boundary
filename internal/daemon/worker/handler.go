package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	proxyHandlers "github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
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

// Handler returns a http.Handler for the API. This can be used on
// its own to mount the Worker API within another web server.
func (w *Worker) handler(props HandlerProperties, sc *session.Cache) (http.Handler, error) {
	const op = "worker.(Worker).handler"
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	h, err := w.handleProxy(props.ListenerConfig, sc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	mux.Handle("/v1/proxy", metric.InstrumentWebsocketWrapper(h))

	genericWrappedHandler := w.wrapGenericHandler(mux, props)
	metricHandler := metric.InstrumentHttpHandler(genericWrappedHandler)
	return metricHandler, nil
}

func (w *Worker) handleProxy(listenerCfg *listenerutil.ListenerConfig, sessionManager *session.Cache) (http.HandlerFunc, error) {
	const op = "worker.(Worker).handleProxy"
	if listenerCfg == nil {
		return nil, fmt.Errorf("%s: missing listener config", op)
	}
	return func(wr http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS == nil {
			event.WriteError(ctx, op, errors.New("no request tls information found"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}

		var sessionId string
	outerCertLoop:
		for _, cert := range r.TLS.PeerCertificates {
			for _, name := range cert.DNSNames {
				if strings.HasPrefix(name, globals.SessionPrefix) {
					sessionId = name
					break outerCertLoop
				}
			}
		}
		if sessionId == "" {
			event.WriteError(ctx, op, errors.New("no session id could be found in peer certificates"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}

		clientIp, clientPort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to understand remote address", "remote_addr", r.RemoteAddr))
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

		userClientIp, err := common.ClientIpFromRequest(ctx, listenerCfg, r)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to determine user ip"))
			wr.WriteHeader(http.StatusInternalServerError)
		}

		sess := sessionManager.Get(sessionId)
		if sess == nil {
			event.WriteError(ctx, op, errors.New("session not found in manager"), event.WithInfo("session_id", sessionId))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}

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

		connCtx, connCancel := context.WithDeadline(ctx, sess.GetExpiration())
		defer connCancel()

		var handshake proxy.ClientHandshake
		if err := wspb.Read(connCtx, conn, &handshake); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error reading handshake from client"))
			if err = conn.Close(websocket.StatusPolicyViolation, "invalid handshake received"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		if len(handshake.GetTofuToken()) < 20 {
			event.WriteError(ctx, op, errors.New("invalid tofu token"))
			if err = conn.Close(websocket.StatusUnsupportedData, "invalid tofu token"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL {
			if err := sess.Cancel(ctx); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to cancel session"))
				if err = conn.Close(websocket.StatusInternalError, "unable to cancel session"); err != nil && !errors.Is(err, io.EOF) {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
			if err = conn.Close(websocket.StatusNormalClosure, "session canceled"); err != nil && !errors.Is(err, io.EOF) {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		if sess.GetTofuToken() != "" {
			if sess.GetTofuToken() != handshake.GetTofuToken() {
				event.WriteError(ctx, op, errors.New("WARNING: mismatched tofu token"), event.WithInfo("session_id", sessionId))
				if err = conn.Close(websocket.StatusPolicyViolation, "tofu token not allowed"); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
		} else {
			if sess.GetStatus() != pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING {
				event.WriteError(ctx, op, errors.New("no tofu token but not in correct session state"), event.WithInfo("session_id", sessionId))
				if err = conn.Close(websocket.StatusInternalError, "refusing to activate session"); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
			if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_UNSPECIFIED {
				err = sess.Activate(ctx, handshake.GetTofuToken())
				if err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("unable to validate session"))
					if err = conn.Close(websocket.StatusInternalError, "unable to activate session"); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
					}
					return
				}
				event.WriteSysEvent(ctx, op, "session successfully activated", "session_id", sessionId)
			}
		}

		// Verify the protocol has a supported proxy before calling AuthorizeConnection
		endpointUrl, err := url.Parse(sess.GetEndpoint())
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("worker failed to parse target endpoint", "endpoint", sess.GetEndpoint()))
			if err = conn.Close(websocket.StatusProtocolError, "unsupported-protocol"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		handleProxyFn, err := proxyHandlers.GetHandler(endpointUrl.Scheme)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("worker received request for unsupported protocol", "protocol", endpointUrl.Scheme))
			if err = conn.Close(websocket.StatusProtocolError, "unsupported-protocol"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		if w.LastStatusSuccess() == nil || w.LastStatusSuccess().WorkerId == "" {
			event.WriteError(ctx, op, errors.New("worker id is empty"))
			if err = conn.Close(websocket.StatusInternalError, "worker id is empty"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		workerId := w.LastStatusSuccess().WorkerId

		var ci *session.ConnInfo
		var connsLeft int32
		ci, connsLeft, err = sess.AuthorizeConnection(ctx, workerId, connCancel)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to authorize connection"))
			if err = conn.Close(websocket.StatusInternalError, "unable to authorize connection"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		event.WriteSysEvent(ctx, op, "connection successfully authorized", "session_id", sessionId, "connection_id", ci.Id)
		defer func() {
			if sessionManager.CloseConnections(ctx, map[string]string{ci.Id: sess.GetId()}) {
				event.WriteSysEvent(ctx, op, "connection closed", "session_id", sessionId, "connection_id", ci.Id)
			}
		}()

		handshakeResult := &proxy.HandshakeResult{
			Expiration:      timestamppb.New(sess.GetExpiration()),
			ConnectionLimit: sess.GetConnectionLimit(),
			ConnectionsLeft: connsLeft,
		}
		if err := wspb.Write(connCtx, conn, handshakeResult); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error sending handshake result to client"))
			if err = conn.Close(websocket.StatusProtocolError, "unable to send handshake result"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		conf := proxyHandlers.Config{
			UserClientIp:   net.ParseIP(userClientIp),
			ClientAddress:  clientAddr,
			ClientConn:     conn,
			RemoteEndpoint: sess.GetEndpoint(),
			Session:        sess,
			ConnectionId:   ci.Id,
		}

		if err := conf.Validate(); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error validating proxy config"))
			if err = conn.Close(websocket.StatusInternalError, "unable to validate proxy parameters"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		credentials := sess.GetCredentials()
		var proxyOpts []proxyHandlers.Option
		if len(credentials) > 0 {
			proxyOpts = append(proxyOpts, proxyHandlers.WithEgressCredentials(credentials))
		}

		if err = handleProxyFn(connCtx, conf, proxyOpts...); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error handling proxy", "session_id", sessionId, "endpoint", sess.GetEndpoint()))
			if err = conn.Close(websocket.StatusInternalError, "unable to establish proxy"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
		}
	}, nil
}

func (w *Worker) wrapGenericHandler(h http.Handler, _ HandlerProperties) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Set the Cache-Control header for all responses returned
		wr.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(wr, r)
	})
}
