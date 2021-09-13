package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/common"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/credentialstores"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"

	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/users"
)

type HandlerProperties struct {
	ListenerConfig *listenerutil.ListenerConfig
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
	callbackInterceptingHandler := wrapHandlerWithCallbackInterceptor(commonWrappedHandler, c)
	printablePathCheckHandler := cleanhttp.PrintablePathCheckHandler(callbackInterceptingHandler, nil)
	eventsHandler, err := common.WrapWithEventsHandler(printablePathCheckHandler, c.conf.Eventer, c.kms)
	if err != nil {
		return nil, err
	}

	return eventsHandler, nil
}

func handleGrpcGateway(c *Controller, props HandlerProperties) (http.Handler, error) {
	// Register*ServiceHandlerServer methods ignore the passed in ctx. Using it
	// now however in case this changes in the future.
	ctx := props.CancelCtx
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: handlers.JSONMarshaler(),
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler()),
		runtime.WithForwardResponseOption(handlers.OutgoingInterceptor),
	)
	hcs, err := host_catalogs.NewService(c.StaticHostRepoFn, c.PluginHostRepoFn, c.HostPluginRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create host catalog handler service: %w", err)
	}
	if err := services.RegisterHostCatalogServiceHandlerServer(ctx, mux, hcs); err != nil {
		return nil, fmt.Errorf("failed to register host catalog service handler: %w", err)
	}
	hss, err := host_sets.NewService(c.StaticHostRepoFn, c.PluginHostRepoFn)
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
	accts, err := accounts.NewService(c.PasswordAuthRepoFn, c.OidcRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create account handler service: %w", err)
	}
	if err := services.RegisterAccountServiceHandlerServer(ctx, mux, accts); err != nil {
		return nil, fmt.Errorf("failed to register account service handler: %w", err)
	}
	authMethods, err := authmethods.NewService(c.kms, c.PasswordAuthRepoFn, c.OidcRepoFn, c.IamRepoFn, c.AuthTokenRepoFn)
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
		c.StaticHostRepoFn,
		c.VaultCredentialRepoFn)
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
	mgs, err := managed_groups.NewService(c.OidcRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed groups handler service: %w", err)
	}
	if err := services.RegisterManagedGroupServiceHandlerServer(ctx, mux, mgs); err != nil {
		return nil, fmt.Errorf("failed to register managed groups service handler: %w", err)
	}
	cs, err := credentialstores.NewService(c.VaultCredentialRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store handler service: %w", err)
	}
	if err := services.RegisterCredentialStoreServiceHandlerServer(ctx, mux, cs); err != nil {
		return nil, fmt.Errorf("failed to register credential store service handler: %w", err)
	}
	cl, err := credentiallibraries.NewService(c.VaultCredentialRepoFn, c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential library handler service: %w", err)
	}
	if err := services.RegisterCredentialLibraryServiceHandlerServer(ctx, mux, cl); err != nil {
		return nil, fmt.Errorf("failed to register credential library service handler: %w", err)
	}

	return mux, nil
}

func wrapHandlerWithCommonFuncs(h http.Handler, c *Controller, props HandlerProperties) http.Handler {
	const op = "controller.wrapHandlerWithCommonFuncs"
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

	disableAuthzFailures := c.conf.DisableAuthorizationFailures ||
		(c.conf.RawConfig.DevController && os.Getenv("BOUNDARY_DEV_SKIP_AUTHZ") != "")
	if disableAuthzFailures {
		event.WriteSysEvent(context.TODO(), op, "AUTHORIZATION CHECKING DISABLED")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = auth.GetTokenFromRequest(ctx, c.kms, r)
		ctx = auth.NewVerifierContext(ctx, c.IamRepoFn, c.AuthTokenRepoFn, c.ServersRepoFn, c.kms, requestInfo)

		// Add general request information to the context. The information from
		// the auth verifier context is pretty specifically curated to
		// authentication/authorization verification so this is more
		// general-purpose.
		//
		// We could use requests.NewRequestContext but this saves an immediate
		// lookup.
		ctx = context.WithValue(ctx, requests.ContextRequestInformationKey, &requests.RequestContext{
			Path:   r.URL.Path,
			Method: r.Method,
		})

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
		if props.ListenerConfig.CorsEnabled == nil || !*props.ListenerConfig.CorsEnabled {
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
			_ = enc.Encode(err)
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

type cmdAttrs struct {
	Command    string      `json:"command,omitempty"`
	Attributes interface{} `json:"attributes,omitempty"`
}

func wrapHandlerWithCallbackInterceptor(h http.Handler, c *Controller) http.Handler {
	logCallbackErrors := os.Getenv("BOUNDARY_LOG_CALLBACK_ERRORS") != ""

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		const op = "controller.wrapHandlerWithCallbackInterceptor"
		ctx := req.Context()
		var err error
		id, err := event.NewId(event.IdField)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to create id for event", "method", req.Method, "url", req.URL.RequestURI()))
			return
		}
		info := &event.RequestInfo{
			EventId:  id,
			Id:       common.GeneratedTraceId(ctx),
			PublicId: "unknown",
			Method:   req.Method,
			Path:     req.URL.RequestURI(),
		}
		ctx, err = event.NewRequestInfoContext(ctx, info)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(req.Context(), op, err, event.WithInfoMsg("unable to create context with request info", "method", req.Method, "url", req.URL.RequestURI()))
			return
		}
		// If this doesn't have a callback suffix on a supported action, serve
		// normally
		if !strings.HasSuffix(req.URL.Path, ":authenticate:callback") {
			h.ServeHTTP(w, req)
			return
		}

		req.URL.Path = strings.TrimSuffix(req.URL.Path, ":callback")

		// How we get the parameters changes based on the method. Right now only
		// GET is supported with query args, but this can support POST with JSON
		// or URL-encoded args. In those cases, the MIME type would have to be
		// checked; for URL-encoded it'd use ParseForm like Get, and for JSON
		// you'd use a json.RawMessage for Attributes consisting of the body. Or
		// something very similar to that.
		var useForm bool
		switch req.Method {
		case http.MethodGet:
			if err := req.ParseForm(); err != nil {
				if logCallbackErrors && c != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("callback error"))
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			useForm = true
		}

		attrs := &cmdAttrs{
			Command: "callback",
		}

		switch {
		case useForm:
			if len(req.Form) > 0 {
				values := make(map[string]interface{}, len(req.Form))
				// This won't handle repeated values. That's fine, at least for now.
				// We can address that if needed, which seems unlikely.
				for k := range req.Form {
					values[k] = req.Form.Get(k)
				}

				if strings.HasSuffix(req.URL.Path, "oidc:authenticate") {
					if s, ok := values["state"].(string); ok {
						stateWrapper, err := oidc.UnwrapMessage(context.Background(), s)
						if err != nil {
							event.WriteError(ctx, op, err, event.WithInfoMsg("error marshaling state"))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						if stateWrapper.AuthMethodId == "" {
							event.WriteError(ctx, op, err, event.WithInfoMsg("missing auth method id"))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						stripped := strings.TrimSuffix(req.URL.Path, "oidc:authenticate")
						req.URL.Path = fmt.Sprintf("%s%s:authenticate", stripped, stateWrapper.AuthMethodId)
					} else {
						event.WriteError(ctx, op, errors.New("missing state parameter"))
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
				}
				attrs.Attributes = values
			}

			attrBytes, err := json.Marshal(attrs)
			if err != nil {
				if logCallbackErrors && c != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error marshaling json"))
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// If there is any existing body, close it as we're going to replace
			// it. It shouldn't be populated in this code path, but you never
			// know.
			if req.Body != nil {
				if err := req.Body.Close(); err != nil {
					if logCallbackErrors && c != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("error closing original request body"))
					}
				}
			}
			bytesReader := bytes.NewReader(attrBytes)
			req.Body = ioutil.NopCloser(bytesReader)
			req.ContentLength = int64(bytesReader.Len())
			req.Header.Set(textproto.CanonicalMIMEHeaderKey("content-type"), "application/json")
			req.Method = http.MethodPost
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
