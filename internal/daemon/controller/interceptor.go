// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias"
	commonSrv "github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/go-version"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	requestInfoMdKey = "request-info"

	// domainErrHeader defines an http header for encoded domain errors from the
	// grpc server.
	domainErrHeader = "x-domain-err"

	// apiErrHeader defines an http header for encoded api errors from the
	// grpc server.
	apiErrHeader = "x-api-err"

	// boundaryClientAgentProduct defines the product name used to identify the
	// Boundary client agent in user-agent parsing and validation logic.
	boundaryClientAgentProduct = "Boundary-client-agent"
)

// Regular expression to parse user-agent product, version, and comments
// Follows the structure defined in RFC 9110: https://datatracker.ietf.org/doc/html/rfc9110#name-user-agent
var userAgentRegex = regexp.MustCompile(`(?P<product>[^\s/()]+)/(?P<version>[^\s()]+)(?: \((?P<comments>[^)]+)\))?`)

// customContextServerStream wraps the grpc.ServerStream interface and lets us
// set a custom context
type customContextServerStream struct {
	grpc.ServerStream
	customContext context.Context
}

func (c *customContextServerStream) Context() context.Context {
	if c.customContext != nil {
		return c.customContext
	}
	return c.ServerStream.Context()
}

// requestCtxUnaryInterceptor creates an unary server interceptor that pulls
// grpc metadata into a ctx for the request. The metadata must be set in an
// upstream http handler/middleware by marshalling a RequestInfo protobuf into
// the requestInfoMdKey header (see: controller.wrapHandlerWithCommonFuncs).
func requestCtxUnaryInterceptor(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	ldapAuthRepoFn common.LdapAuthRepoFactory,
	kms *kms.Kms,
	ticket string,
	eventer *event.Eventer,
) (grpc.UnaryServerInterceptor, error) {
	const op = "controller.requestCtxUnaryInterceptor"
	if err := sharedRequestInterceptorValidation(
		ctx,
		op,
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		kms,
		ticket,
		eventer,
	); err != nil {
		return nil, err
	}

	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		updatedCtx, err := sharedRequestInterceptorLogic(
			interceptorCtx,
			op,
			iamRepoFn,
			authTokenRepoFn,
			serversRepoFn,
			passwordAuthRepoFn,
			oidcAuthRepoFn,
			ldapAuthRepoFn,
			kms,
			ticket,
			eventer,
		)
		if err != nil {
			return nil, err
		}
		return handler(updatedCtx, req)
	}, nil
}

// requestCtxStreamInterceptor creates a stream server interceptor that pulls
// grpc metadata into a ctx for the request. The metadata must be set in an
// upstream http handler/middleware by marshalling a RequestInfo protobuf into
// the requestInfoMdKey header (see: controller.wrapHandlerWithCommonFuncs).
func requestCtxStreamInterceptor(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	ldapAuthRepoFn common.LdapAuthRepoFactory,
	kms *kms.Kms,
	ticket string,
	eventer *event.Eventer,
) (grpc.StreamServerInterceptor, error) {
	const op = "controller.requestCtxStreamInterceptor"
	if err := sharedRequestInterceptorValidation(
		ctx,
		op,
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		kms,
		ticket,
		eventer,
	); err != nil {
		return nil, err
	}
	return func(srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		updatedCtx, err := sharedRequestInterceptorLogic(
			ss.Context(),
			op,
			iamRepoFn,
			authTokenRepoFn,
			serversRepoFn,
			passwordAuthRepoFn,
			oidcAuthRepoFn,
			ldapAuthRepoFn,
			kms,
			ticket,
			eventer,
		)
		if err != nil {
			return err
		}
		css := &customContextServerStream{
			ServerStream:  ss,
			customContext: updatedCtx,
		}
		return handler(srv, css)
	}, nil
}

func sharedRequestInterceptorValidation(
	ctx context.Context,
	op errors.Op,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	kms *kms.Kms,
	ticket string,
	eventer *event.Eventer,
) error {
	if iamRepoFn == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing iam repo function")
	}
	if authTokenRepoFn == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing auth token repo function")
	}
	if serversRepoFn == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing server repo function")
	}
	if kms == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	if ticket == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ticket")
	}
	if eventer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing eventer")
	}

	return nil
}

func sharedRequestInterceptorLogic(
	interceptorCtx context.Context,
	op errors.Op,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	ldapAuthRepoFn common.LdapAuthRepoFactory,
	kms *kms.Kms,
	ticket string,
	eventer *event.Eventer,
) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(interceptorCtx)
	if !ok {
		return nil, errors.New(interceptorCtx, errors.Internal, op, "No metadata")
	}

	values := md.Get(requestInfoMdKey)
	if len(values) == 0 {
		return nil, errors.New(interceptorCtx, errors.Internal, op, "Missing request metadata")
	}
	if len(values) > 1 {
		return nil, errors.New(interceptorCtx, errors.Internal, op, fmt.Sprintf("expected 1 value for %s metadata and got %d", requestInfoMdKey, len(values)))
	}

	decoded, err := base58.FastBase58Decoding(values[0])
	if err != nil {
		return nil, errors.Wrap(interceptorCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("unable to decode request info"))
	}
	var requestInfo authpb.RequestInfo
	if err := proto.Unmarshal(decoded, &requestInfo); err != nil {
		return nil, errors.Wrap(interceptorCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("unable to unmarshal request info"))
	}
	switch {
	case requestInfo.Ticket == "":
		return nil, errors.New(interceptorCtx, errors.Internal, op, "Invalid context (missing ticket)")
	case subtle.ConstantTimeCompare([]byte(requestInfo.Ticket), []byte(ticket)) != 1:
		return nil, errors.New(interceptorCtx, errors.Internal, op, "Invalid context (bad ticket)")
	}

	interceptorCtx = auth.NewVerifierContextWithAccounts(interceptorCtx, iamRepoFn, authTokenRepoFn, serversRepoFn, passwordAuthRepoFn, oidcAuthRepoFn, ldapAuthRepoFn, kms, &requestInfo)

	// Add general request information to the context. The information from
	// the auth verifier context is pretty specifically curated to
	// authentication/authorization verification so this is more
	// general-purpose.
	//
	// We could use requests.NewRequestContext but this saves an immediate
	// lookup.
	interceptorCtx = context.WithValue(interceptorCtx, requests.ContextRequestInformationKey, &requests.RequestContext{
		Path:   requestInfo.Path,
		Method: requestInfo.Method,
	})

	// This event request info is required by downstream handlers
	info := &event.RequestInfo{
		EventId:  requestInfo.EventId,
		Id:       requestInfo.TraceId,
		PublicId: requestInfo.PublicId,
		Method:   requestInfo.Method,
		Path:     requestInfo.Path,
		ClientIp: requestInfo.ClientIp,
	}
	interceptorCtx, err = event.NewRequestInfoContext(interceptorCtx, info)
	if err != nil {
		return nil, errors.Wrap(interceptorCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("unable to create context with request info"))
	}
	interceptorCtx, err = event.NewEventerContext(interceptorCtx, eventer)
	if err != nil {
		return nil, errors.Wrap(interceptorCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("unable to create context with eventer"))
	}

	return interceptorCtx, err // not convinced we want to wrap every error and turn them into domain errors...
}

func correlationIdInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.correlationIdInterceptor"
	return func(interceptorCtx context.Context, req any,
		_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		md, ok := metadata.FromIncomingContext(interceptorCtx)
		if !ok {
			return nil, errors.New(interceptorCtx, errors.Internal, op, "no metadata")
		}

		values := md.Get(globals.CorrelationIdKey)
		if len(values) == 0 {
			return nil, errors.New(interceptorCtx, errors.Internal, op, "missing correlation id metadata")
		}
		if len(values) > 1 {
			return nil, errors.New(interceptorCtx, errors.Internal, op, fmt.Sprintf("expected 1 value for %s metadata and got %d", globals.CorrelationIdKey, len(values)))
		}
		correlationId := values[0]

		// Validate the correlationId
		if _, err := uuid.ParseUUID(correlationId); err != nil {
			return nil, errors.Wrap(interceptorCtx, err, op, errors.WithMsg("failed to validated correlation id"))
		}

		interceptorCtx, err := event.NewCorrelationIdContext(interceptorCtx, correlationId)
		if err != nil {
			return nil, errors.Wrap(interceptorCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("unable to create context with correlation id"))
		}

		// call the handler...
		return handler(interceptorCtx, req)
	}
}

func errorInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.errorInterceptor"
	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		// call the handler...
		h, handlerErr := handler(interceptorCtx, req)

		// if there's an error and it's a domain err, then encode it into the
		if handlerErr != nil {
			var domainErr *errors.Err
			isDomainErr := errors.As(handlerErr, &domainErr)
			if isDomainErr {
				pbErr := errors.ToPbErrors(domainErr)
				var buf []byte
				var err error
				if buf, err = proto.Marshal(pbErr); err != nil {
					return h, status.Errorf(codes.Internal, "unable to marshal domain error: %s", err)
				}
				if err := grpc.SetHeader(interceptorCtx, metadata.Pairs(domainErrHeader, base58.FastBase58Encoding(buf))); err != nil {
					return h, status.Errorf(codes.Internal, "unable to set domain error header: %s", err)
				}
				return h, handlerErr
			}

			var apiErr *handlers.ApiError
			isApiError := errors.As(handlerErr, &apiErr)
			if isApiError {
				pbErr := &pberrors.ApiError{
					ApiError: apiErr.Inner,
					Status:   apiErr.Status,
				}
				var buf []byte
				var err error
				if buf, err = proto.Marshal(pbErr); err != nil {
					return h, status.Errorf(codes.Internal, "unable to marshal api error: %s", err)
				}
				if err := grpc.SetHeader(interceptorCtx, metadata.Pairs(apiErrHeader, base58.FastBase58Encoding(buf))); err != nil {
					return h, status.Errorf(codes.Internal, "unable to set api error header: %s", err)
				}
				return h, handlerErr
			}
		}
		return h, handlerErr
	}
}

// aliasResolutionInterceptor returns a grpc.UnaryServerInterceptor that resolves
// alias values in the request to their corresponding destination ids. If no
// alias is found or the alias has no destination id, an error is returned.
// For an field in the request to be considered for alias resolution, it must
// be annotated with the Aliasable proto option.
func aliasResolutionInterceptor(
	_ context.Context,
	aliasRepoFn common.AliasRepoFactory,
) grpc.UnaryServerInterceptor {
	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		reqMsg, ok := req.(proto.Message)
		if !ok {
			return nil, handlers.InvalidArgumentErrorf("The request was not a proto.Message.", nil)
		}

		r, err := aliasRepoFn()
		if err != nil {
			return nil, err
		}
		interceptorCtx, err = alias.ResolveRequestIds(interceptorCtx, reqMsg, r)
		if err != nil {
			// At this point, the request is unauthorized, therefore return a
			// static error rather than exposing what the result of
			// `ResolveRequestIds` was.
			return nil, handlers.NotFoundError()
		}
		return handler(interceptorCtx, req)
	}
}

func statusCodeInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.statusCodeInterceptor"
	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		// call the handler...
		h, handlerErr := handler(interceptorCtx, req)

		// if a service handler returns nil, nil then we want to single a 204
		// response to the proxy with no resp msg
		if isNil(h) && handlerErr == nil {
			if err := handlers.SetStatusCode(interceptorCtx, http.StatusNoContent); err != nil {
				return &pb.EmptyResponse{}, err
			}
			return &pb.EmptyResponse{}, nil
		}

		return h, handlerErr
	}
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

func eventsRequestInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.eventsRequestInterceptor"
	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		var userAgents []*event.UserAgent
		if md, ok := metadata.FromIncomingContext(interceptorCtx); ok {
			if values := md.Get(userAgentsKey); len(values) > 0 {
				userAgents = parseUserAgents(values[0])
			}
		}
		if msg, ok := req.(proto.Message); ok {
			// Clone the request before writing it to the audit log,
			// in case downstream interceptors modify it.
			clonedMsg := proto.Clone(msg)
			request := &event.Request{
				Details:    clonedMsg,
				UserAgents: userAgents,
			}
			if err := event.WriteAudit(interceptorCtx, op, event.WithRequest(&event.Request{Details: clonedMsg})); err != nil {
				return req, status.Errorf(codes.Internal, "unable to write request msg audit: %s", err)
			}
			if err := event.WriteObservation(interceptorCtx, op, event.WithRequest(request)); err != nil {
				return req, status.Errorf(codes.Internal, "unable to write request msg observation: %s", err)
			}
		}

		return handler(interceptorCtx, req)
	}
}

// parseUserAgents extracts structured UserAgent data from a raw User-Agent header string.
// Version validation is applied only to Boundary-client-agent entries, which are excluded
// if the version starts with 'v' or is not a valid semantic version.
// Comments are split and normalized into a slice of strings.
func parseUserAgents(rawUserAgent string) []*event.UserAgent {
	var userAgents []*event.UserAgent
	matches := userAgentRegex.FindAllStringSubmatch(rawUserAgent, -1)

	for _, match := range matches {
		product := strings.TrimSpace(match[1])
		agentVersion := strings.TrimSpace(match[2])

		// Only apply version validation for Boundary-client-agent
		if product == boundaryClientAgentProduct {
			if strings.HasPrefix(agentVersion, "v") {
				// Invalid version format (starting with 'v')
				continue
			}
			if _, err := version.NewSemver(agentVersion); err != nil {
				// Invalid version
				continue
			}
		}

		agentData := &event.UserAgent{
			Product:        product,
			ProductVersion: agentVersion,
		}

		if len(match) > 3 && match[3] != "" {
			// Clean up and split comments
			commentsRaw := strings.Split(match[3], ";")
			var comments []string
			for _, c := range commentsRaw {
				if trimmed := strings.TrimSpace(c); trimmed != "" {
					comments = append(comments, trimmed)
				}
			}
			if len(comments) > 0 {
				agentData.Comments = comments
			}
		}
		userAgents = append(userAgents, agentData)
	}
	return userAgents
}

func eventsResponseInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.eventsResponseInterceptor"
	return func(interceptorCtx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error,
	) {
		// call the handler...
		resp, err := handler(interceptorCtx, req)

		if msg, ok := resp.(proto.Message); ok {
			// Clone the response before writing it to the audit log,
			// in case downstream interceptors modify it.
			clonedMsg := proto.Clone(msg)
			if err := event.WriteAudit(interceptorCtx, op, event.WithResponse(&event.Response{Details: clonedMsg})); err != nil {
				return req, status.Errorf(codes.Internal, "unable to write response msg audit: %s", err)
			}
			if err := event.WriteObservation(interceptorCtx, op, event.WithResponse(&event.Response{Details: clonedMsg})); err != nil {
				return req, status.Errorf(codes.Internal, "unable to write response msg observation: %s", err)
			}
		}

		return resp, err
	}
}

func requestMaxDurationInterceptor(_ context.Context, maxRequestDuration time.Duration) grpc.UnaryServerInterceptor {
	const op = "controller.requestMaxDurationInterceptor"
	return func(interceptorCtx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		withTimeout, cancel := context.WithTimeout(interceptorCtx, maxRequestDuration)
		defer cancel()
		return handler(withTimeout, req)
	}
}

func workerRequestInfoInterceptor(ctx context.Context, eventer *event.Eventer) (grpc.UnaryServerInterceptor, error) {
	const op = "worker.requestInfoInterceptor"
	if eventer == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing eventer")
	}
	return func(interceptorCtx context.Context,
		req any,
		srvInfo *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		var err error
		id, err := event.NewId(event.IdPrefix)
		if err != nil {
			event.WriteError(interceptorCtx, op, err, event.WithInfoMsg("unable to create id for event", "method", srvInfo.FullMethod))
			return nil, status.Errorf(codes.Internal, "Error creating id for event: %v", err)
		}
		info := &event.RequestInfo{
			EventId: id,
			Id:      commonSrv.GeneratedTraceId(interceptorCtx),
			Method:  srvInfo.FullMethod,
		}
		interceptorCtx, err = event.NewRequestInfoContext(interceptorCtx, info)
		if err != nil {
			event.WriteError(interceptorCtx, op, err, event.WithInfoMsg("unable to create context with request info", "method", srvInfo.FullMethod))
			return nil, status.Errorf(codes.Internal, "Error creating context with request info: %v", err)
		}
		interceptorCtx, err = event.NewEventerContext(interceptorCtx, eventer)
		if err != nil {
			event.WriteError(interceptorCtx, op, err, event.WithInfoMsg("unable to create context with eventer", "method", srvInfo.FullMethod))
			return nil, status.Errorf(codes.Internal, "Error creating context with eventer: %v", err)
		}
		// call the handler...
		return handler(interceptorCtx, req)
	}, nil
}

func recoveryHandler() grpc_recovery.RecoveryHandlerFuncContext {
	const op = "controller.recoveryHandler"
	return func(ctx context.Context, p any) (err error) {
		event.WriteError(
			ctx,
			op,
			fmt.Errorf("recovered from panic: %v", p),
			event.WithInfo("stack", string(debug.Stack())),
		)

		return status.Errorf(codes.Internal, "%v", p)
	}
}
