// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/subtle"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coder/websocket"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	proxyHandlers "github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/sdk/pbs/proxy"
	"github.com/hashicorp/boundary/sdk/wspb"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type HandlerProperties struct {
	ListenerConfig *listenerutil.ListenerConfig
}

// Handler returns a http.Handler for the API. This can be used on
// its own to mount the Worker API within another web server.
func (w *Worker) handler(props HandlerProperties, sm session.Manager) (http.Handler, error) {
	const op = "worker.(Worker).handler"
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	var h http.Handler
	h, err := w.handleProxy(props.ListenerConfig, sm)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	h = proxyHandlers.ProxyHandlerCounter(h)
	mux.Handle("/v1/proxy", metric.InstrumentWebsocketWrapper(h))

	genericWrappedHandler := w.wrapGenericHandler(mux, props)
	metricHandler := metric.InstrumentHttpHandler(genericWrappedHandler)
	return metricHandler, nil
}

func (w *Worker) handleProxy(listenerCfg *listenerutil.ListenerConfig, sessionManager session.Manager) (http.HandlerFunc, error) {
	const op = "worker.(Worker).handleProxy"
	if listenerCfg == nil {
		return nil, fmt.Errorf("%s: missing listener config", op)
	}
	return func(wr http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS == nil {
			event.WriteError(ctx, op, stderrors.New("no request tls information found"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}

		var sessionId string
	outerCertLoop:
		for _, cert := range r.TLS.PeerCertificates {
			for _, name := range cert.DNSNames {
				if strings.HasPrefix(name, fmt.Sprintf("%s_", globals.SessionPrefix)) {
					sessionId = name
					break outerCertLoop
				}
			}
		}
		if sessionId == "" {
			event.WriteError(ctx, op, stderrors.New("no session id could be found in peer certificates"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}

		clientIp, clientPort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to understand remote address", "remote_addr", r.RemoteAddr))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		numPort, err := strconv.ParseUint(clientPort, 10, 16)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to understand remote port"))
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		clientAddr := &net.TCPAddr{
			IP:   net.ParseIP(clientIp),
			Port: int(numPort),
		}

		userClientIp, err := common.ClientIpFromRequest(ctx, listenerCfg, r)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to determine user ip"))
			wr.WriteHeader(http.StatusInternalServerError)
		}

		sess := sessionManager.Get(sessionId)
		if sess == nil {
			event.WriteError(ctx, op, stderrors.New("session not found locally"), event.WithInfo("session_id", sessionId))
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
		if len(handshake.GetTofuToken()) != 20 {
			event.WriteError(ctx, op, stderrors.New("invalid tofu token"))
			if err = conn.Close(websocket.StatusUnsupportedData, "invalid tofu token"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL {
			if err := sess.RequestCancel(ctx); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to cancel session"))
				if err = conn.Close(websocket.StatusInternalError, "unable to cancel session"); err != nil && !stderrors.Is(err, io.EOF) {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
			if err = conn.Close(websocket.StatusNormalClosure, "session canceled"); err != nil && !stderrors.Is(err, io.EOF) {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		if sess.GetTofuToken() != "" {
			if subtle.ConstantTimeCompare([]byte(sess.GetTofuToken()), []byte(handshake.GetTofuToken())) != 1 {
				event.WriteError(ctx, op, stderrors.New("WARNING: mismatched tofu token"), event.WithInfo("session_id", sessionId))
				if err = conn.Close(websocket.StatusPolicyViolation, "tofu token not allowed"); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
		} else {
			if sess.GetStatus() != pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING {
				event.WriteError(ctx, op, stderrors.New("no tofu token but not in correct session state"), event.WithInfo("session_id", sessionId))
				if err = conn.Close(websocket.StatusInternalError, "refusing to activate session"); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
				}
				return
			}
			if handshake.Command == proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_UNSPECIFIED {
				err = sess.RequestActivate(ctx, handshake.GetTofuToken())
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

		if w.LastRoutingInfoSuccess() == nil || w.LastRoutingInfoSuccess().WorkerId == "" {
			event.WriteError(ctx, op, stderrors.New("worker id is empty"))
			if err = conn.Close(websocket.StatusInternalError, "worker id is empty"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		workerId := w.LastRoutingInfoSuccess().WorkerId

		var acResp *pbs.AuthorizeConnectionResponse
		var connsLeft int32
		acResp, connsLeft, err = sess.RequestAuthorizeConnection(ctx, workerId, connCancel)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to authorize connection"))
			if err = conn.Close(websocket.StatusInternalError, "unable to authorize connection"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		event.WriteSysEvent(ctx, op, "connection successfully authorized", "session_id", sessionId, "connection_id", acResp.GetConnectionId())

		// Wrapping the client websocket with a `net.Conn` implementation that
		// records the bytes that go across Read() and Write().
		cc := &countingConn{Conn: websocket.NetConn(connCtx, conn, websocket.MessageBinary)}
		err = sess.ApplyConnectionCounterCallbacks(acResp.GetConnectionId(), cc.BytesRead, cc.BytesWritten)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to set counter callbacks for session connection"))
			err = conn.Close(websocket.StatusInternalError, "unable to set counter callbacks for session connection")
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		defer func() {
			ccd := map[string]*session.ConnectionCloseData{
				acResp.GetConnectionId(): {
					SessionId: sess.GetId(),
					BytesUp:   cc.BytesRead(),
					BytesDown: cc.BytesWritten(),
				},
			}
			if sessionManager.RequestCloseConnections(ctx, ccd) {
				event.WriteSysEvent(ctx, op, "connection closed", "session_id", sessionId, "connection_id", acResp.GetConnectionId())
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

		endpointUrl, err := url.Parse(sess.GetEndpoint())
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("worker failed to parse target endpoint", "endpoint", sess.GetEndpoint()))
			if err = conn.Close(websocket.StatusProtocolError, "unable to parse endpoint"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}
		protocolCtx := acResp.GetProtocolContext()

		pDialer, err := proxyHandlers.GetEndpointDialer(ctx, endpointUrl.Host, workerId, acResp, w.downstreamReceiver, proxyHandlers.WithDnsServerAddress(w.conf.WorkerDnsServer))
		if err != nil {
			conn.Close(proxyHandlers.WebsocketStatusProtocolSetupError, "unable to get endpoint dialer")
			event.WriteError(ctx, op, err)
			return
		}

		// Verify the protocol has a supported proxy before calling RequestAuthorizeConnection
		handleProxyFn, err := proxyHandlers.GetHandler(workerId, acResp.GetProtocolContext())
		if err != nil {
			conn.Close(proxyHandlers.WebsocketStatusProtocolSetupError, "unable to get proxy handler")
			event.WriteError(ctx, op, err)
			return
		}
		decryptFn, err := w.credDecryptFn(ctx)
		if err != nil {
			conn.Close(proxyHandlers.WebsocketStatusProtocolSetupError, "error getting decryption function")
			event.WriteError(ctx, op, err)
		}
		runProxy, err := handleProxyFn(ctx, ctx, decryptFn, cc, pDialer, acResp.GetConnectionId(), protocolCtx, w.recorderManager, proxyHandlers.WithLogger(w.logger))
		if err != nil {
			conn.Close(proxyHandlers.WebsocketStatusProtocolSetupError, "unable to setup proxying")

			switch {
			case errors.Match(errors.T(errors.WindowsRDPClientEarlyDisconnection), err):
				// This is known behavior with Windows Remote Desktop clients and does not
				// indicate a problem with the worker or the proxy.
				// There is no need to log an error event here.
			default:
				event.WriteError(ctx, op, err)
			}
			return
		}

		// We connect connection only after we have confirmed as much as we can
		// that we can establish the proxy.
		endpointAddr := pDialer.LastConnectionAddr()
		connectionInfo := &pbs.ConnectConnectionRequest{
			ConnectionId:       acResp.GetConnectionId(),
			ClientTcpAddress:   clientAddr.IP.String(),
			ClientTcpPort:      uint32(clientAddr.Port),
			EndpointTcpAddress: endpointAddr.Ip(), // endpointAddr.ip is assigned via net.IP and therefore should already be formatted correctly
			EndpointTcpPort:    endpointAddr.Port(),
			Type:               endpointUrl.Scheme,
			UserClientIp:       userClientIp,
		}
		if err = sess.RequestConnectConnection(ctx, connectionInfo); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error requesting connect connection", "session_id", sess.GetId(), "connection_id", acResp.GetConnectionId()))
			if err = conn.Close(websocket.StatusInternalError, "unable to establish proxy"); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing client connection"))
			}
			return
		}

		runProxy()
	}, nil
}

// credDecryptFn returns a DecryptFn if the worker is a pki worker with
// WorkerAuthStorage defined. An error is returned if there is an error
// loading the node credentials.
func (w *Worker) credDecryptFn(ctx context.Context) (proxyHandlers.DecryptFn, error) {
	const op = "worker.(*Worker).credDecryptFn"
	if w.WorkerAuthStorage == nil {
		return nil, nil
	}
	was := w.WorkerAuthStorage
	var opts []nodeenrollment.Option
	if !util.IsNil(w.conf.WorkerAuthStorageKms) {
		opts = append(opts, nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms))
	}
	nodeCreds, err := types.LoadNodeCredentials(ctx, was, nodeenrollment.CurrentId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return func(ctx context.Context, from []byte, to proto.Message) error {
		if err := nodeenrollment.DecryptMessage(ctx, from, nodeCreds, to); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	}, nil
}

func (w *Worker) wrapGenericHandler(h http.Handler, _ HandlerProperties) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Set the Cache-Control header for all responses returned
		wr.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(wr, r)
	})
}
