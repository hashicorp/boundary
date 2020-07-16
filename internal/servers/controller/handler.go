package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/globals"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/authenticate"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/groups"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_catalogs"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_sets"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/hosts"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/orgs"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/projects"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/roles"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/users"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/kr/pretty"
)

type HandlerProperties struct {
	ListenerConfig *configutil.Listener
}

// Handler returns an http.Handler for the services. This can be used on
// its own to mount the Vault API within another web server.
func (c *Controller) handler(props HandlerProperties) (http.Handler, error) {
	// Create the muxer to handle the actual endpoints
	mux := http.NewServeMux()

	h, err := handleGrpcGateway(c)
	if err != nil {
		return nil, err
	}
	mux.Handle("/v1/", h)

	mux.Handle("/", handleUi(c))

	corsWrappedHandler := wrapHandlerWithCors(mux, props)
	commonWrappedHandler := wrapHandlerWithCommonFuncs(corsWrappedHandler, c, props)

	return commonWrappedHandler, nil
}

func handleGrpcGateway(c *Controller) (http.Handler, error) {
	// Register*ServiceHandlerServer methods ignore the passed in ctx.  Using the baseContext now just in case this changes
	// in the future, at which point we'll want to be using the baseContext.
	ctx := c.baseContext
	mux := runtime.NewServeMux(runtime.WithProtoErrorHandler(handlers.ErrorHandler(c.logger)))
	hcs, err := host_catalogs.NewService(c.StaticHostRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create host catalog handler service: %w", err)
	}
	if err := services.RegisterHostCatalogServiceHandlerServer(ctx, mux, hcs); err != nil {
		return nil, fmt.Errorf("failed to register host catalog service handler: %w", err)
	}
	if err := services.RegisterHostSetServiceHandlerServer(ctx, mux, &host_sets.Service{}); err != nil {
		return nil, fmt.Errorf("failed to register host set service handler: %w", err)
	}
	if err := services.RegisterHostServiceHandlerServer(ctx, mux, &hosts.Service{}); err != nil {
		return nil, fmt.Errorf("failed to register host service handler: %w", err)
	}
	auths, err := authenticate.NewService(c.IamRepoFn, c.AuthTokenRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication handler service: %w", err)
	}
	if err := services.RegisterAuthenticationServiceHandlerServer(ctx, mux, auths); err != nil {
		return nil, fmt.Errorf("failed to register authenticate service handler: %w", err)
	}
	os, err := orgs.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create org handler service: %w", err)
	}
	if err := services.RegisterOrgServiceHandlerServer(ctx, mux, os); err != nil {
		return nil, fmt.Errorf("failed to register org service handler: %w", err)
	}
	ps, err := projects.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create project handler service: %w", err)
	}
	if err := services.RegisterProjectServiceHandlerServer(ctx, mux, ps); err != nil {
		return nil, fmt.Errorf("failed to register project service handler: %w", err)
	}
	us, err := users.NewService(c.IamRepoFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create user handler service: %w", err)
	}
	if err := services.RegisterUserServiceHandlerServer(ctx, mux, us); err != nil {
		return nil, fmt.Errorf("failed to register user service handler: %w", err)
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

	return mux, nil
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

	logUrls := os.Getenv("WATCHTOWER_LOG_URLS") != ""

	disableAuthzFailures := c.conf.DisableAuthorizationFailures ||
		(c.conf.RawConfig.DevController && os.Getenv("WATCHTOWER_DEV_SKIP_AUTHZ") != "")
	if disableAuthzFailures {
		c.logger.Warn("AUTHORIZATION CHECKING DISABLED")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logUrls {
			c.logger.Trace("request received", "url", r.URL.String())
		}

		// Set the Cache-Control header for all responses returned
		w.Header().Set("Cache-Control", "no-store")

		// Start with the request context and our timeout
		ctx, cancelFunc := context.WithTimeout(r.Context(), maxRequestDuration)
		defer cancelFunc()

		userId := "u_anon"
		var res *perms.Resource
		var act action.Type
		var err error
		var authzResults *perms.ACLResults

		if r.Method == http.MethodOptions {
			// Don't perform authorization checking for preflight requests, at
			// least for now. We could add it later if we wanted as an action on
			// global or something but likely it would just be enabled/disabled
			// per listener instead.
			goto AUTHZ_FINISHED
		}

		// Perform authz checking
		res, act, err = decorateAuthParams(r)
		if err != nil {
			c.logger.Trace("error reading auth parameters from URL", "url", r.URL.Path, "error", err)
			// Maybe this isn't the best option, but a URL we can't parse from
			// an auth perspective is probably just an invalid URL altogether.
			// Treating it as a bad request can be perceived to be less leaky
			// than a 404.
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// The resource is only nil with no error if the path is something
		// unauthenticated, e.g. the UI serving path.
		if res != nil {
			authzResults, userId, err = c.performAuthzCheck(ctx, r, res, act)
			if err != nil {
				c.logger.Error("error during authz check", "error", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if userId == "" || !authzResults.Allowed {
				// TODO: Decide whether to remove this
				if disableAuthzFailures {
					c.logger.Info("failed authz info for request", "resource", pretty.Sprint(res), "user_id", userId, "action", act.String())
				} else {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}

	AUTHZ_FINISHED:
		// Add the user ID to the context
		ctx = context.WithValue(ctx, globals.ContextUserIdValue, userId)
		// Add a size limiter if desired
		if maxRequestSize > 0 {
			ctx = context.WithValue(ctx, "max_request_size", maxRequestSize)
		}
		ctx = context.WithValue(ctx, "original_request_path", r.URL.Path)
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

			err := &api.Error{
				Status: http.StatusForbidden,
				Code:   "origin forbidden",
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
	})
}

func decorateAuthParams(r *http.Request) (*perms.Resource, action.Type, error) {
	if r == nil {
		return nil, action.Unknown, errors.New("decorate auth params: incoming request is nil")
	}

	// Remove trailing and leading slashes
	trimmedPath := strings.Trim(r.URL.Path, "/")
	if !strings.HasPrefix(trimmedPath, "v1") {
		// Don't look for auth params for requests to fetch the UI
		return nil, action.Unknown, nil
	}
	splitPath := strings.Split(strings.TrimPrefix(trimmedPath, "v1"), "/")
	splitLen := len(splitPath)
	if splitLen == 0 {
		return nil, action.Unknown, fmt.Errorf("decorate auth params: invalid path")
	}

	var act action.Type
	var typStr string
	scp := scope.Global
	res := &perms.Resource{
		ScopeId: scope.Global.String(),
	}

	// Handle non-custom types. We'll deal with custom types, including list,
	// after parsing the path.
	switch r.Method {
	case "GET":
		act = action.Read
	case "POST":
		act = action.Create
	case "PATCH":
		act = action.Update
	case "DELETE":
		act = action.Delete
	default:
		return nil, action.Unknown, fmt.Errorf("decorate auth params: unknown method %q", r.Method)
	}

	// Look for a custom action
	colonSplit := strings.Split(splitPath[splitLen-1], ":")
	switch len(colonSplit) {
	case 1:
		// No custom action specified
	case 2:
		actStr := colonSplit[len(colonSplit)-1]
		act = action.Map[actStr]
		if act == action.Unknown || act == action.All {
			return nil, action.Unknown, fmt.Errorf("decorate auth params: unknown action %q", actStr)
		}
		// Keep going with the logic without the custom action
		splitPath[splitLen-1] = colonSplit[0]
	default:
		return nil, action.Unknown, fmt.Errorf("decorate auth params: unexpected number of colons in last segment %q", colonSplit[len(colonSplit)-1])
	}

	// Walk backwards. As we walk backwards we look for scopes and figure out if
	// we're operating on a resource or a collection. We also populate the pin.
	// The rules for the pin are as follows:
	//
	// * If the last segment is a collection, the pin is the immediately
	// preceding ID
	//
	// * If the last segment is an ID, the pin is the immediately preceding ID
	// not including the last segment
	//
	// * If at the end of the logic the pin is the id of a scope ("global",
	// "o_...", "p_...") then there is no pin. The scopes are already enclosing
	// so a pin is redundant.
	nextIdIsPin := true
	for i := splitLen - 1; i >= 0; i-- {
		segment := splitPath[i]

		// Collections don't contain underscores; every resource ID does.
		segmentIsCollection := !strings.Contains(segment, "_")

		if !segmentIsCollection && i != splitLen-1 && nextIdIsPin {
			res.Pin = segment
			nextIdIsPin = false
		}

		// Update the scope. Set it to org only if it's at global (that way we
		// don't override project with org). We have to check if it's one less
		// than the length of the split because operating on the id of a scope
		// is actually in the enclosing scope (since you're in the parent scope
		// operating on a child scope).
		switch segment {
		case "projects":
			if i < splitLen-2 {
				scp = scope.Project
				res.ScopeId = splitPath[i+1]
			}
		case "orgs":
			if scp == scope.Global {
				if i < splitLen-2 {
					scp = scope.Org
					res.ScopeId = splitPath[i+1]
				}
			}
		}

		if segment == "" {
			// This could be the case if we have an action like
			// /orgs/o_1234/projects/p_1234/:set-defaults to act on the project
			// itself but within its own scope
			continue
		}

		if typStr == "" {
			// The resource check takes place inside the type check because if
			// we've identified the type we have either already identified the
			// right-most resource ID or we're operating on a collection, so
			// this prevents us from finding a different ID earlier in the path.
			//
			// We continue on with the enclosing loop anyways though to ensure
			// we find the right scope.
			if res.Id == "" && !segmentIsCollection {
				res.Id = segment
			} else {
				// Every collection is the plural of the resource type so drop
				// the last 's'
				if !strings.HasSuffix(segment, "s") {
					return nil, action.Unknown, fmt.Errorf("decorate auth params: invalid collection syntax for %q", segment)
				}
				typStr = strings.TrimSuffix(segment, "s")
			}
		}
	}

	if typStr != "" {
		res.Type = resource.Map[typStr]
		if res.Type == resource.Unknown {
			return nil, action.Unknown, fmt.Errorf("decorate auth params: unknown resource type %q", typStr)
		}
	} else if res.Id == "" {
		return nil, action.Unknown, errors.New("decorate auth params: id and type both not found")
	}

	// If we're operating on a collection (that is, the ID is blank) and it's a
	// GET, it's actually a list
	if res.Id == "" && act == action.Read {
		act = action.List
	}

	// If the pin ended up being a scope, nil it out
	if res.Pin != "" {
		if res.Pin == "global" ||
			strings.HasPrefix(res.Pin, "o_") ||
			strings.HasPrefix(res.Pin, "p_") {
			res.Pin = ""
		}
	}

	return res, act, nil
}

type tokenFormat int

const (
	authTokenTypeUnknown tokenFormat = iota
	authTokenTypeBearer
	authTokenTypeSplitCookie
)

const (
	headerAuthMethod    = "Authorization"
	httpOnlyCookieName  = "wt-http-token-cookie"
	jsVisibleCookieName = "wt-js-token-cookie"
)

func (c *Controller) performAuthzCheck(ctx context.Context, req *http.Request, res *perms.Resource, act action.Type) (*perms.ACLResults, string, error) {
	userId := "u_anon"

	if res == nil {
		return nil, userId, errors.New("perform authz check: res is nil")
	}
	var receivedTokenType tokenFormat
	var fullToken, token, publicId string

	// First, get the token, either from the authorization header or from split
	// cookies
	{
		if authHeader := req.Header.Get("Authorization"); authHeader != "" {
			headerSplit := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
			if len(headerSplit) == 2 && strings.EqualFold(strings.TrimSpace(headerSplit[0]), "bearer") {
				receivedTokenType = authTokenTypeBearer
				fullToken = strings.TrimSpace(headerSplit[1])
			}
		}
		if receivedTokenType != authTokenTypeBearer {
			var httpCookiePayload string
			var jsCookiePayload string
			if hc, err := req.Cookie(httpOnlyCookieName); err == nil {
				httpCookiePayload = hc.Value
			}
			if jc, err := req.Cookie(jsVisibleCookieName); err == nil {
				jsCookiePayload = jc.Value
			}
			if httpCookiePayload != "" && jsCookiePayload != "" {
				receivedTokenType = authTokenTypeSplitCookie
				fullToken = jsCookiePayload + httpCookiePayload
			}
		}

		if receivedTokenType == authTokenTypeUnknown || fullToken == "" {
			// We didn't find auth info or a client screwed up and put in a
			// blank header instead of nothing at all, so carry on as the
			// anonymous user
			goto GRANTSLOOKUP
		}

		splitFullToken := strings.Split(fullToken, "_")
		if len(splitFullToken) != 3 {
			return nil, userId, fmt.Errorf("perform authz check: unexpected number of segments in token, expected %d, found %d", 3, len(splitFullToken))
		}

		token = splitFullToken[2]
		publicId = strings.Join(splitFullToken[0:2], "_")

		if receivedTokenType == authTokenTypeUnknown || token == "" || publicId == "" {
			return nil, userId, fmt.Errorf("perform authz check: after parsing, could not find valid token")
		}
	}

	// Validate the token and fetch the corresponding user ID
	{
		tokenRepo, err := c.AuthTokenRepoFn()
		if err != nil {
			return nil, userId, fmt.Errorf("perform authz check: failed to get authtoken repo: %w", err)
		}

		at, err := tokenRepo.ValidateToken(ctx, publicId, token)
		if err != nil {
			return nil, userId, fmt.Errorf("perform authz check: failed to validate token: %w", err)
		}
		if at != nil {
			userId = at.GetIamUserId()
		}
	}

GRANTSLOOKUP:
	var parsedGrants []perms.Grant
	var grantPairs []perms.GrantPair
	// Fetch and parse grants for this user ID
	{
		iamRepo, err := c.IamRepoFn()
		if err != nil {
			return nil, userId, fmt.Errorf("perform authz check: failed to get iam repo: %w", err)
		}
		grantPairs, err = iamRepo.GrantsForUser(ctx, userId)
		if err != nil {
			return nil, userId, fmt.Errorf("perform authz check: failed to query for user grants: %w", err)
		}
		parsedGrants = make([]perms.Grant, 0, len(grantPairs))
		for _, pair := range grantPairs {
			parsed, err := perms.Parse(pair.ScopeId, userId, pair.Grant)
			if err != nil {
				return nil, userId, fmt.Errorf("perform authz check: failed to parse grant %#v: %w", pair.Grant, err)
			}
			parsedGrants = append(parsedGrants, parsed)
		}
	}

	acl := perms.NewACL(parsedGrants...)
	allowed := acl.Allowed(*res, act)
	return &allowed, userId, nil
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
