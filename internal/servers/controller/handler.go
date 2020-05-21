package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/globals"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/projects"
)

type HandlerProperties struct {
	ListenerConfig *configutil.Listener
}

// Handler returns an http.Handler for the services. This can be used on
// its own to mount the Vault API within another web server.
func (c *Controller) handler(props HandlerProperties) http.Handler {
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	mux.Handle("/v1/", handleGrpcGateway(c))

	corsWrappedHandler := wrapHandlerWithCors(mux, c, props)
	commonWrappedHandler := wrapHandlerWithCommonFuncs(corsWrappedHandler, c, props)

	return commonWrappedHandler
}

func handleGrpcGateway(c *Controller) http.Handler {
	// Register*ServiceHandlerServer methods ignore the passed in ctx.  Using the baseContext now just in case this changes
	// in the future, at which point we'll want to be using the baseContext.
	ctx := c.baseContext
	mux := runtime.NewServeMux()
	services.RegisterHostCatalogServiceHandlerServer(ctx, mux, &host_catalogs.Service{})
	services.RegisterHostSetServiceHandlerServer(ctx, mux, &host_sets.Service{})
	services.RegisterHostServiceHandlerServer(ctx, mux, &hosts.Service{})
	services.RegisterProjectServiceHandlerServer(ctx, mux, projects.NewService(c.IamRepo))

	return mux
}

func wrapHandlerWithCommonFuncs(h http.Handler, c *Controller, props HandlerProperties) http.Handler {
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
	var defaultOrgId string
	if c != nil && c.conf != nil {
		defaultOrgId = c.conf.DefaultOrgId
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if defaultOrgId != "" {
			splitPath := strings.Split(r.URL.Path, "/")
			if len(splitPath) >= 3 && splitPath[2] == "projects" {
				http.Redirect(w, r, path.Join("/v1/orgs", defaultOrgId, strings.Join(splitPath[2:], "/")), 307)
				return
			}
		}

		// Set the Cache-Control header for all responses returned
		w.Header().Set("Cache-Control", "no-store")

		// Start with the request context
		ctx := r.Context()
		var cancelFunc context.CancelFunc
		// Add our timeout
		ctx, cancelFunc = context.WithTimeout(ctx, maxRequestDuration)
		// Add a size limiter if desired
		if maxRequestSize > 0 {
			ctx = context.WithValue(ctx, "max_request_size", maxRequestSize)
		}
		ctx = context.WithValue(ctx, "original_request_path", r.URL.Path)
		r = r.WithContext(ctx)

		h.ServeHTTP(w, r)
		cancelFunc()
		return
	})
}

func wrapHandlerWithCors(h http.Handler, c *Controller, props HandlerProperties) http.Handler {
	allowedMethods := []string{
		http.MethodDelete,
		http.MethodGet,
		http.MethodOptions,
		http.MethodPost,
		http.MethodPatch,
	}

	allowedOrigins := props.ListenerConfig.CorsAllowedOrigins

	allowedHeaders := append([]string{
		"Content-Type",
		"X-Requested-With",
		"Authorization",
	}, props.ListenerConfig.CorsAllowedHeaders...)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !props.ListenerConfig.CorsEnabled {
			h.ServeHTTP(w, req)
			return
		}

		origin := req.Header.Get("Origin")

		if origin == "" {
			// Serve directly
			h.ServeHTTP(w, req)
			return
		}

		// Check origin
		var valid bool
		switch {
		case len(allowedOrigins) == 0:
			// not valid

		case len(allowedOrigins) == 1 && allowedOrigins[0] == "*":
			valid = true

		default:
			valid = strutil.StrListContains(allowedOrigins, origin)
		}
		if !valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)

			err := &api.Error{
				Status: api.Int(http.StatusForbidden),
				Code:   api.String("origin forbidden"),
			}

			enc := json.NewEncoder(w)
			enc.Encode(err)
			return
		}

		if req.Method == http.MethodOptions &&
			!strutil.StrListContains(allowedMethods, req.Header.Get("Access-Control-Request-Method")) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")

		// Apply headers for preflight requests
		if req.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", "300")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, req)
		return
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
