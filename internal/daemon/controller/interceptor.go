package controller

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"runtime/debug"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	commonSrv "github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/requests"
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
)

// requestCtxInterceptor creates an unary server interceptor that pulls grpc
// metadata into a ctx for the request.  The metadata must be set in an upstream
// http handler/middleware by marshalling a RequestInfo protobuf into the
// requestInfoMdKey header (see: controller.wrapHandlerWithCommonFuncs).
func requestCtxInterceptor(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	kms *kms.Kms,
	ticket string,
	eventer *event.Eventer,
) (grpc.UnaryServerInterceptor, error) {
	const op = "controller.requestCtxInterceptor"
	if iamRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing iam repo function")
	}
	if authTokenRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token repo function")
	}
	if serversRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing server repo function")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	if ticket == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ticket")
	}
	if eventer == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing eventer")
	}
	// Authorization unary interceptor function to handle authorize per RPC call
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
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
		case requestInfo.Ticket != ticket:
			return nil, errors.New(interceptorCtx, errors.Internal, op, "Invalid context (bad ticket)")
		}

		interceptorCtx = auth.NewVerifierContextWithAccounts(interceptorCtx, iamRepoFn, authTokenRepoFn, serversRepoFn, passwordAuthRepoFn, oidcAuthRepoFn, kms, &requestInfo)

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

		// Calls the handler
		h, err := handler(interceptorCtx, req)

		return h, err // not convinced we want to wrap every error and turn them into domain errors...
	}, nil
}

func errorInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.errorInterceptor"
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error,
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

func statusCodeInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.statusCodeInterceptor"
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error,
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

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

func auditRequestInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.auditRequestInterceptor"
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error,
	) {
		if msg, ok := req.(proto.Message); ok {
			// Clone the request before writing it to the audit log,
			// in case downstream interceptors modify it.
			clonedMsg := proto.Clone(msg)
			if err := event.WriteAudit(interceptorCtx, op, event.WithRequest(&event.Request{Details: clonedMsg})); err != nil {
				return req, status.Errorf(codes.Internal, "unable to write request msg audit: %s", err)
			}
		}

		return handler(interceptorCtx, req)
	}
}

func auditResponseInterceptor(
	_ context.Context,
) grpc.UnaryServerInterceptor {
	const op = "controller.auditResponseInterceptor"
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error,
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
		}

		return resp, err
	}
}

func workerRequestInfoInterceptor(ctx context.Context, eventer *event.Eventer) (grpc.UnaryServerInterceptor, error) {
	const op = "worker.requestInfoInterceptor"
	if eventer == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing eventer")
	}
	return func(interceptorCtx context.Context,
		req interface{},
		srvInfo *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
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
	return func(ctx context.Context, p interface{}) (err error) {
		event.WriteError(
			ctx,
			op,
			fmt.Errorf("recovered from panic: %v", p),
			event.WithInfo("stack", string(debug.Stack())),
		)

		return status.Errorf(codes.Internal, "%v", p)
	}
}
