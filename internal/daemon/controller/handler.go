// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/apptokens"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/billing"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentialstores"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/health"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/policies"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/session_recordings"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/storage_buckets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/daemon/controller/internal/metric"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	opsservices "github.com/hashicorp/boundary/internal/gen/ops/services"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
)

type HandlerProperties struct {
	ListenerConfig *listenerutil.ListenerConfig
	CancelCtx      context.Context
}

const uiPath = "/"

// createMuxWithEndpoints performs all response logic for boundary, using isUiRequest
// for unified logic between responses and headers.
func createMuxWithEndpoints(c *Controller, props HandlerProperties) (http.Handler, func(req *http.Request) bool, error) {
	grpcGwMux := newGrpcGatewayMux()
	if err := registerGrpcGatewayEndpoints(props.CancelCtx, grpcGwMux, gatewayDialOptions(c.apiGrpcServerListener)...); err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", ratelimit.Handler(c.baseContext, c.getRateLimiter, grpcGwMux))
	mux.Handle(uiPath, handleUi(c))

	isUiRequest := func(req *http.Request) bool {
		_, p := mux.Handler(req)
		// check to see if the matched pattern is for the ui
		return p == uiPath
	}

	return mux, isUiRequest, nil
}

// apiHandler returns an http.Handler for the services. This can be used on
// its own to mount the Controller API within another web server.
func (c *Controller) apiHandler(props HandlerProperties) (http.Handler, error) {
	mux, isUiRequest, err := createMuxWithEndpoints(c, props)
	if err != nil {
		return nil, err
	}

	corsWrappedHandler := wrapHandlerWithCors(mux, props)
	commonWrappedHandler := wrapHandlerWithCommonFuncs(corsWrappedHandler, c, props)
	callbackInterceptingHandler := wrapHandlerWithCallbackInterceptor(commonWrappedHandler, c)
	printablePathCheckHandler := cleanhttp.PrintablePathCheckHandler(callbackInterceptingHandler, nil)
	eventsHandler, err := common.WrapWithEventsHandler(c.baseContext, printablePathCheckHandler, c.conf.Eventer, c.kms, props.ListenerConfig)
	if err != nil {
		return nil, err
	}
	metricsHandler := metric.InstrumentApiHandler(eventsHandler)

	// This wrap MUST be performed last. If you add a new wrapper, do so above.
	return listenerutil.WrapCustomHeadersHandler(metricsHandler, props.ListenerConfig, isUiRequest), nil
}

// GetHealthHandler returns a gRPC Gateway mux that is registered against the
// controller's gRPC health service to make it accessible from an HTTP API.
func (c *Controller) GetHealthHandler(lcfg *listenerutil.ListenerConfig) (http.Handler, error) {
	const op = "controller.(Controller).GetHealthHandler"
	if lcfg == nil {
		return nil, fmt.Errorf("%s: received nil listener config", op)
	}

	healthGrpcGwMux := newGrpcGatewayMux()
	err := registerHealthGrpcGatewayEndpoint(c.baseContext, healthGrpcGwMux, gatewayDialOptions(c.apiGrpcServerListener)...)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to register health service handler: %w", op, err)
	}

	wrapped := wrapHandlerWithCommonFuncs(healthGrpcGwMux, c, HandlerProperties{lcfg, c.baseContext})
	return common.WrapWithEventsHandler(c.baseContext, wrapped, c.conf.Eventer, c.kms, lcfg)
}

func registerHealthGrpcGatewayEndpoint(ctx context.Context, gwMux *runtime.ServeMux, dialOptions ...grpc.DialOption) error {
	return opsservices.RegisterHealthServiceHandlerFromEndpoint(ctx, gwMux, gatewayTarget, dialOptions)
}

func (c *Controller) registerGrpcServices(s *grpc.Server) error {
	// We have to check against the current services because the gRPC lib treats a duplicate
	// register call as an error and os.Exits.
	currentServices := s.GetServiceInfo()

	if _, ok := currentServices[services.HostCatalogService_ServiceDesc.ServiceName]; !ok {
		hcs, err := host_catalogs.NewService(
			c.baseContext,
			c.StaticHostRepoFn,
			c.PluginHostRepoFn,
			c.PluginRepoFn,
			c.IamRepoFn,
			c.HostCatalogRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create host catalog handler service: %w", err)
		}
		services.RegisterHostCatalogServiceServer(s, hcs)
	}
	if _, ok := currentServices[services.HostSetService_ServiceDesc.ServiceName]; !ok {
		hss, err := host_sets.NewService(c.baseContext, c.StaticHostRepoFn, c.PluginHostRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create host set handler service: %w", err)
		}
		services.RegisterHostSetServiceServer(s, hss)
	}
	if _, ok := currentServices[services.HostService_ServiceDesc.ServiceName]; !ok {
		hs, err := hosts.NewService(c.baseContext, c.StaticHostRepoFn, c.PluginHostRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create host handler service: %w", err)
		}
		services.RegisterHostServiceServer(s, hs)
	}
	if _, ok := currentServices[services.AccountService_ServiceDesc.ServiceName]; !ok {
		accts, err := accounts.NewService(c.baseContext, c.PasswordAuthRepoFn, c.OidcRepoFn, c.LdapRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create account handler service: %w", err)
		}
		services.RegisterAccountServiceServer(s, accts)
	}
	if _, ok := currentServices[services.AuthMethodService_ServiceDesc.ServiceName]; !ok {
		authMethods, err := authmethods.NewService(
			c.baseContext,
			c.kms,
			c.PasswordAuthRepoFn,
			c.OidcRepoFn,
			c.IamRepoFn,
			c.AuthTokenRepoFn,
			c.LdapRepoFn,
			c.AuthMethodRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create auth method handler service: %w", err)
		}
		services.RegisterAuthMethodServiceServer(s, authMethods)
	}
	if _, ok := currentServices[services.AuthTokenService_ServiceDesc.ServiceName]; !ok {
		authtoks, err := authtokens.NewService(c.baseContext, c.AuthTokenRepoFn, c.IamRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create auth token handler service: %w", err)
		}
		services.RegisterAuthTokenServiceServer(s, authtoks)
	}
	if _, ok := currentServices[services.ScopeService_ServiceDesc.ServiceName]; !ok {
		os, err := scopes.NewServiceFn(c.baseContext, c.IamRepoFn, c.kms, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create scope handler service: %w", err)
		}
		services.RegisterScopeServiceServer(s, os)
	}
	if _, ok := currentServices[services.UserService_ServiceDesc.ServiceName]; !ok {
		us, err := users.NewService(c.baseContext, c.IamRepoFn, c.TargetAliasRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create user handler service: %w", err)
		}
		services.RegisterUserServiceServer(s, us)
	}
	if _, ok := currentServices[services.StorageBucketService_ServiceDesc.ServiceName]; !ok {
		sbs, err := storage_buckets.NewServiceFn(
			c.baseContext,
			c.PluginStorageBucketRepoFn,
			c.IamRepoFn,
			c.PluginRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
			c.ControllerExtension)
		if err != nil {
			return fmt.Errorf("failed to create storage bucket handler service: %w", err)
		}
		services.RegisterStorageBucketServiceServer(s, sbs)
	}
	if _, ok := currentServices[services.PolicyService_ServiceDesc.ServiceName]; !ok {
		ps, err := policies.NewServiceFn(
			c.baseContext,
			c.IamRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
			c.ControllerExtension,
		)
		if err != nil {
			return fmt.Errorf("failed to create policy handler service: %w", err)
		}
		services.RegisterPolicyServiceServer(s, ps)
	}
	if _, ok := currentServices[services.SessionRecordingService_ServiceDesc.ServiceName]; !ok {
		srs, err := session_recordings.NewServiceFn(
			c.baseContext,
			c.IamRepoFn,
			c.ServersRepoFn,
			c.workerRPCGracePeriod,
			c.kms,
			c.conf.RawConfig.Controller.MaxPageSize,
			c.ControllerExtension)
		if err != nil {
			return fmt.Errorf("failed to create session recording handler service: %w", err)
		}
		services.RegisterSessionRecordingServiceServer(s, srs)
	}
	if _, ok := currentServices[services.TargetService_ServiceDesc.ServiceName]; !ok {
		ts, err := targets.NewService(
			c.baseContext,
			c.kms,
			c.TargetRepoFn,
			c.IamRepoFn,
			c.ServersRepoFn,
			c.SessionRepoFn,
			c.PluginHostRepoFn,
			c.StaticHostRepoFn,
			c.VaultCredentialRepoFn,
			c.StaticCredentialRepoFn,
			c.TargetAliasRepoFn,
			c.downstreamWorkers,
			c.workerRPCGracePeriod,
			c.conf.RawConfig.Controller.MaxPageSize,
			c.ControllerExtension,
		)
		if err != nil {
			return fmt.Errorf("failed to create target handler service: %w", err)
		}
		services.RegisterTargetServiceServer(s, ts)
	}
	if _, ok := currentServices[services.GroupService_ServiceDesc.ServiceName]; !ok {
		gs, err := groups.NewService(c.baseContext, c.IamRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create group handler service: %w", err)
		}
		services.RegisterGroupServiceServer(s, gs)
	}
	if _, ok := currentServices[services.RoleService_ServiceDesc.ServiceName]; !ok {
		rs, err := roles.NewService(c.baseContext, c.IamRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create role handler service: %w", err)
		}
		services.RegisterRoleServiceServer(s, rs)
	}
	if _, ok := currentServices[services.SessionService_ServiceDesc.ServiceName]; !ok {
		ss, err := sessions.NewService(c.baseContext, c.SessionRepoFn, c.IamRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create session handler service: %w", err)
		}
		services.RegisterSessionServiceServer(s, ss)
	}
	if _, ok := currentServices[services.ManagedGroupService_ServiceDesc.ServiceName]; !ok {
		mgs, err := managed_groups.NewService(c.baseContext, c.OidcRepoFn, c.LdapRepoFn, c.conf.RawConfig.Controller.MaxPageSize)
		if err != nil {
			return fmt.Errorf("failed to create managed groups handler service: %w", err)
		}
		services.RegisterManagedGroupServiceServer(s, mgs)
	}
	if _, ok := currentServices[services.CredentialStoreService_ServiceDesc.ServiceName]; !ok {
		cs, err := credentialstores.NewService(
			c.baseContext,
			c.IamRepoFn,
			c.VaultCredentialRepoFn,
			c.StaticCredentialRepoFn,
			c.CredentialStoreRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create credential store handler service: %w", err)
		}
		services.RegisterCredentialStoreServiceServer(s, cs)
	}
	if _, ok := currentServices[services.CredentialLibraryService_ServiceDesc.ServiceName]; !ok {
		cl, err := credentiallibraries.NewService(
			c.baseContext,
			c.IamRepoFn,
			c.VaultCredentialRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create credential library handler service: %w", err)
		}
		services.RegisterCredentialLibraryServiceServer(s, cl)
	}
	if _, ok := currentServices[services.WorkerService_ServiceDesc.ServiceName]; !ok {
		ws, err := workers.NewService(c.baseContext, c.ServersRepoFn, c.IamRepoFn, c.WorkerAuthRepoStorageFn,
			c.downstreamWorkers)
		if err != nil {
			return fmt.Errorf("failed to create worker handler service: %w", err)
		}
		services.RegisterWorkerServiceServer(s, ws)
	}
	if _, ok := currentServices[services.AliasService_ServiceDesc.ServiceName]; !ok {
		as, err := aliases.NewService(
			c.baseContext,
			c.TargetAliasRepoFn,
			c.IamRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create alias handler service: %w", err)
		}
		services.RegisterAliasServiceServer(s, as)
	}
	if _, ok := currentServices[services.CredentialService_ServiceDesc.ServiceName]; !ok {
		c, err := credentials.NewService(
			c.baseContext,
			c.IamRepoFn,
			c.StaticCredentialRepoFn,
			c.conf.RawConfig.Controller.MaxPageSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create credential handler service: %w", err)
		}
		services.RegisterCredentialServiceServer(s, c)
	}
	if _, ok := currentServices[opsservices.HealthService_ServiceDesc.ServiceName]; !ok {
		hs := health.NewService()
		opsservices.RegisterHealthServiceServer(s, hs)
		c.HealthService = hs
	}
	if _, ok := currentServices[services.BillingService_ServiceDesc.ServiceName]; !ok {
		bs, err := billing.NewService(c.baseContext, c.BillingRepoFn)
		if err != nil {
			return fmt.Errorf("failed to create billing handler service: %w", err)
		}
		services.RegisterBillingServiceServer(s, bs)
	}

	return nil
}

func registerGrpcGatewayEndpoints(ctx context.Context, gwMux *runtime.ServeMux, dialOptions ...grpc.DialOption) error {
	conn, err := grpc.NewClient(gatewayTarget, dialOptions...)
	if err != nil {
		return err
	}
	// Register*ServiceHandlerServer methods ignore the passed in context.
	// Passing it in anyways in case this changes in the future.
	if err := services.RegisterHostCatalogServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register host catalog service handler: %w", err)
	}
	if err := services.RegisterHostSetServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register host set service handler: %w", err)
	}
	if err := services.RegisterHostServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register host service handler: %w", err)
	}
	if err := services.RegisterAccountServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register account service handler: %w", err)
	}
	if err := services.RegisterAuthMethodServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register auth method service handler: %w", err)
	}
	if err := services.RegisterAuthTokenServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register auth token service handler: %w", err)
	}
	if err := services.RegisterScopeServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register scope service handler: %w", err)
	}
	if err := services.RegisterUserServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register user service handler: %w", err)
	}
	if err := services.RegisterTargetServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register target service handler: %w", err)
	}
	if err := services.RegisterGroupServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register group service handler: %w", err)
	}
	if err := services.RegisterRoleServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register role service handler: %w", err)
	}
	if err := services.RegisterSessionServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register session service handler: %w", err)
	}
	if err := services.RegisterManagedGroupServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register managed groups service handler: %w", err)
	}
	if err := services.RegisterCredentialStoreServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register credential store service handler: %w", err)
	}
	if err := services.RegisterCredentialLibraryServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register credential library service handler: %w", err)
	}
	if err := services.RegisterWorkerServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register worker service handler: %w", err)
	}
	if err := services.RegisterCredentialServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register credential service handler: %w", err)
	}
	if err := services.RegisterSessionRecordingServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register session recording service handler: %w", err)
	}
	if err := services.RegisterStorageBucketServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register storage bucket service handler: %w", err)
	}
	if err := services.RegisterAliasServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register alias service handler: %w", err)
	}
	if err := services.RegisterPolicyServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register policy handler: %w", err)
	}
	if err := services.RegisterBillingServiceHandler(ctx, gwMux, conn); err != nil {
		return fmt.Errorf("failed to register billing service handler: %w", err)
	}

	return nil
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
		requestInfo := authpb.RequestInfo{
			Path:                 r.URL.Path,
			Method:               r.Method,
			DisableAuthzFailures: disableAuthzFailures,
		}

		requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = auth.GetTokenFromRequest(ctx, c.kms, r)
		ctx = context.WithValue(ctx, globals.ContextAuthTokenPublicIdKey, requestInfo.PublicId)

		if info, ok := event.RequestInfoFromContext(ctx); ok {
			// piggyback some eventing fields with the auth info proto message
			requestInfo.EventId = info.EventId
			requestInfo.TraceId = info.Id
			requestInfo.ClientIp = info.ClientIp
			requestInfo.Actions = getActions(info.Path)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(ctx, op, errors.New("unable to read event request info from context"))
			return
		}

		// Serialize the request info to send it across the wire to the
		// grpc-gateway via an http header
		requestInfo.Ticket = c.apiGrpcGatewayTicket // allows the grpc-gateway to verify the request info came from it's in-memory companion http proxy
		marshalledRequestInfo, err := proto.Marshal(&requestInfo)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error marshaling request info"))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Use the default grpc-gateway mapping rule to pass the request info as
		// metadata.
		// See: https://pkg.go.dev/github.com/grpc-ecosystem/grpc-gateway/runtime#DefaultHeaderMatcher
		r.Header.Set("Grpc-Metadata-"+requestInfoMdKey, base58.FastBase58Encoding(marshalledRequestInfo))

		// Set the context back on the request
		r = r.Clone(ctx)
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

	allowedResponseHeaders := strings.Join([]string{
		"Retry-After",
		"RateLimit",
		"RateLimit-Policy",
	}, ", ")

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
			// When allowed origins is "*" we want to return that rather than
			// round-tripping any user-specified value
			origin = "*"

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
		w.Header().Set("Access-Control-Expose-Headers", allowedResponseHeaders)

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
	Command    string `json:"command,omitempty"`
	Attributes any    `json:"attributes,omitempty"`
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

		req.URL.Path = strings.TrimSuffix(req.URL.Path, ":"+auth.CallbackAction)

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
				values := make(map[string]any, len(req.Form))
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
			req.Body = io.NopCloser(bytesReader)
			req.ContentLength = int64(bytesReader.Len())
			req.Header.Set(textproto.CanonicalMIMEHeaderKey("content-type"), "application/json")
			req.Method = http.MethodPost
		}

		h.ServeHTTP(w, req)
	})
}

// getActions takes in a URL Path and returns the actions from the URL
func getActions(urlPath string) []string {
	// Remove any query parameters
	urlPath = strings.Split(urlPath, "?")[0]

	lastPart := path.Base(urlPath)

	_, rest, _ := strings.Cut(lastPart, ":")
	if rest == "" {
		return []string{}
	}

	// Split the rest on ":", returning all actions and sub-actions
	return strings.Split(rest, ":")
}
