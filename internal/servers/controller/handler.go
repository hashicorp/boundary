package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"google.golang.org/grpc/codes"

	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/users"
	"google.golang.org/protobuf/encoding/protojson"
)

type HandlerProperties struct {
	ListenerConfig *configutil.Listener
	CancelCtx      context.Context
}

// Handler returns an http.Handler for the services. This can be used on
// its own to mount the Controller API within another web server.
func (c *Controller) handler(props HandlerProperties) (http.Handler, error) {
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	h, err := handleGrpcGateway(c, props)
	if err != nil {
		return nil, err
	}
	mux.Handle("/v1/", h)
	mux.Handle("/", handleUi(c))

	corsWrappedHandler := wrapHandlerWithCors(mux, props)
	commonWrappedHandler := wrapHandlerWithCommonFuncs(corsWrappedHandler, c, props)
	printablePathCheckHandler := cleanhttp.PrintablePathCheckHandler(commonWrappedHandler, nil)

	return printablePathCheckHandler, nil
}

func handleGrpcGateway(c *Controller, props HandlerProperties) (http.Handler, error) {
	// Register*ServiceHandlerServer methods ignore the passed in ctx.  Using
	// the a context now just in case this changes in the future
	ctx := props.CancelCtx
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: &runtime.JSONPb{
				MarshalOptions: protojson.MarshalOptions{
					// Ensures the json marshaler uses the snake casing as defined in the proto field names.
					UseProtoNames: true,
					// Do not add fields set to zero value to json.
					EmitUnpopulated: false,
				},
				UnmarshalOptions: protojson.UnmarshalOptions{
					// Allows requests to contain unknown fields.
					DiscardUnknown: true,
				},
			},
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler(c.logger)),
		runtime.WithForwardResponseOption(handlers.OutgoingInterceptor),
	)
	hcs, err := host_catalogs.NewService(c.StaticHostRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create host catalog handler service: %w", err)
	}
	if err := services.RegisterHostCatalogServiceHandlerServer(ctx, mux, hcs); err != nil {
		return nil, fmt.Errorf("failed to register host catalog service handler: %w", err)
	}
	hss, err := host_sets.NewService(c.StaticHostRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create host set handler service: %w", err)
	}
	if err := services.RegisterHostSetServiceHandlerServer(ctx, mux, hss); err != nil {
		return nil, fmt.Errorf("failed to register host set service handler: %w", err)
	}
	hs, err := hosts.NewService(c.StaticHostRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create host handler service: %w", err)
	}
	if err := services.RegisterHostServiceHandlerServer(ctx, mux, hs); err != nil {
		return nil, fmt.Errorf("failed to register host service handler: %w", err)
	}
	accts, err := accounts.NewService(c.PasswordAuthRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create account handler service: %w", err)
	}
	if err := services.RegisterAccountServiceHandlerServer(ctx, mux, accts); err != nil {
		return nil, fmt.Errorf("failed to register account service handler: %w", err)
	}
	authMethods, err := authmethods.NewService(c.kms, c.PasswordAuthRepoFn, c.IamRepoFn, c.AuthTokenRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth method handler service: %w", err)
	}
	if err := services.RegisterAuthMethodServiceHandlerServer(ctx, mux, authMethods); err != nil {
		return nil, fmt.Errorf("failed to register auth method service handler: %w", err)
	}
	authtoks, err := authtokens.NewService(c.AuthTokenRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth token handler service: %w", err)
	}
	if err := services.RegisterAuthTokenServiceHandlerServer(ctx, mux, authtoks); err != nil {
		return nil, fmt.Errorf("failed to register auth token service handler: %w", err)
	}
	os, err := scopes.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create scope handler service: %w", err)
	}
	if err := services.RegisterScopeServiceHandlerServer(ctx, mux, os); err != nil {
		return nil, fmt.Errorf("failed to register scope service handler: %w", err)
	}
	us, err := users.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create user handler service: %w", err)
	}
	if err := services.RegisterUserServiceHandlerServer(ctx, mux, us); err != nil {
		return nil, fmt.Errorf("failed to register user service handler: %w", err)
	}
	ts, err := targets.NewService(
		c.kms,
		c.TargetRepoFn,
		c.IamRepoFn,
		c.ServersRepoFn,
		c.SessionRepoFn,
		c.StaticHostRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create target handler service: %w", err)
	}
	if err := services.RegisterTargetServiceHandlerServer(ctx, mux, ts); err != nil {
		return nil, fmt.Errorf("failed to register target service handler: %w", err)
	}
	gs, err := groups.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create group handler service: %w", err)
	}
	if err := services.RegisterGroupServiceHandlerServer(ctx, mux, gs); err != nil {
		return nil, fmt.Errorf("failed to register group service handler: %w", err)
	}
	rs, err := roles.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create role handler service: %w", err)
	}
	if err := services.RegisterRoleServiceHandlerServer(ctx, mux, rs); err != nil {
		return nil, fmt.Errorf("failed to register role service handler: %w", err)
	}
	ss, err := sessions.NewService(c.SessionRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create session handler service: %w", err)
	}
	if err := services.RegisterSessionServiceHandlerServer(ctx, mux, ss); err != nil {
		return nil, fmt.Errorf("failed to register session service handler: %w", err)
	}

	return mux, nil
}

// generatedTraceId returns a boundary generated TraceId or "" if an error occurs when generating
// the id.
func generatedTraceId() string {
	t, err := base62.Random(20)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("gtraceid_%s", t)
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

	logUrls := os.Getenv("BOUNDARY_LOG_URLS") != ""

	disableAuthzFailures := c.conf.DisableAuthorizationFailures ||
		(c.conf.RawConfig.DevController && os.Getenv("BOUNDARY_DEV_SKIP_AUTHZ") != "")
	if disableAuthzFailures {
		c.logger.Warn("AUTHORIZATION CHECKING DISABLED")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logUrls {
			c.logger.Trace("request received", "method", r.Method, "url", r.URL.RequestURI())
		}

		// Set the Cache-Control header for all responses returned
		w.Header().Set("Cache-Control", "no-store")

		// Start with the request context and our timeout
		ctx, cancelFunc := context.WithTimeout(r.Context(), maxRequestDuration)
		defer cancelFunc()

		// Add a size limiter if desired
		if maxRequestSize > 0 {
			ctx = context.WithValue(ctx, globals.ContextMaxRequestSizeTypeKey, maxRequestSize)
		}

		// Add values for authn/authz checking
		requestInfo := auth.RequestInfo{
			Path:                 r.URL.Path,
			Method:               r.Method,
			DisableAuthzFailures: disableAuthzFailures,
		}

		requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = auth.GetTokenFromRequest(c.logger, c.kms, r)
		ctx = auth.NewVerifierContext(ctx, c.logger, c.IamRepoFn, c.AuthTokenRepoFn, c.ServersRepoFn, c.kms, requestInfo)

		// Set the context back on the request
		r = r.WithContext(ctx)

		h.ServeHTTP(w, r)
	})
}

func wrapHandlerWithCors(h http.Handler, props HandlerProperties) http.Handler {
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

			err := handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "origin forbidden")

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
