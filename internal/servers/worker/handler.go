package worker

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/globals"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

type HandlerProperties struct {
	ListenerConfig *configutil.Listener
}

// Handler returns an http.Handler for the API. This can be used on
// its own to mount the Vault API within another web server.
func (w *Worker) handler(props HandlerProperties) http.Handler {
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	mux.Handle("/v1/proxy", w.handleProxy())

	genericWrappedHandler := w.wrapGenericHandler(mux, props)

	return genericWrappedHandler
}

func (w *Worker) handleProxy() http.HandlerFunc {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.logger.Error("no request TLS information found")
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		jobId := r.TLS.ServerName

		jobInfoRaw, valid := w.jobInfoMap.LoadAndDelete(jobId)
		if !valid {
			w.logger.Error("job not found in info map", "job_id", jobId)
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		jobInfo := jobInfoRaw.(*pb.Session)

		opts := &websocket.AcceptOptions{
			Subprotocols: []string{globals.TcpProxyV1},
		}
		conn, err := websocket.Accept(wr, r, opts)
		if err != nil {
			w.logger.Error("error during websocket upgrade", "error", err)
			wr.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Later calls will cause this to noop if they return a different status
		defer conn.Close(websocket.StatusNormalClosure, "done")

		connCtx, connCancel := context.WithCancel(r.Context())
		w.cancellationMap.Store(jobId, connCancel)
		defer func() {
			cancel, loaded := w.cancellationMap.LoadAndDelete(jobId)
			if !loaded {
				return
			}
			cancel.(context.CancelFunc)()
		}()

		var handshake proxy.Handshake
		if err := wspb.Read(connCtx, conn, &handshake); err != nil {
			w.logger.Error("error reading nonce from client", "error", err)
			wr.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(handshake.GetTofuToken()) < 20 {
			w.logger.Error("invalid tofu token")
			wr.WriteHeader(http.StatusBadRequest)
			return
		}

		switch conn.Subprotocol() {
		case globals.TcpProxyV1:
			w.handleTcpProxyV1(connCtx, conn, jobInfo)
		default:
			conn.Close(websocket.StatusProtocolError, "unsupported-protocol")
			return
		}
	})
}

func (w *Worker) wrapGenericHandler(h http.Handler, props HandlerProperties) http.Handler {
	var maxRequestDuration time.Duration
	var maxRequestSize int64
	if props.ListenerConfig != nil {
		maxRequestDuration = props.ListenerConfig.MaxRequestDuration
		maxRequestSize = props.ListenerConfig.MaxRequestSize
	}
	if maxRequestDuration == 0 {
		maxRequestDuration = globals.DefaultMaxRequestDuration
	}
	if maxRequestSize == 0 {
		maxRequestSize = globals.DefaultMaxRequestSize
	}
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Set the Cache-Control header for all responses returned
		wr.Header().Set("Cache-Control", "no-store")

		// Start with the request context
		ctx := r.Context()
		var cancelFunc context.CancelFunc
		// Add our timeout
		ctx, cancelFunc = context.WithTimeout(ctx, maxRequestDuration)
		// Add a size limiter if desired
		if maxRequestSize > 0 {
			ctx = context.WithValue(ctx, globals.ContextMaxRequestSizeTypeKey, maxRequestSize)
		}
		ctx = context.WithValue(ctx, globals.ContextOriginalRequestPathTypeKey, r.URL.Path)
		r = r.WithContext(ctx)

		h.ServeHTTP(wr, r)
		cancelFunc()
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
