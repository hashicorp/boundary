package controller

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"

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
	kms *kms.Kms,
	ticket string,
) (grpc.UnaryServerInterceptor, error) {
	const op = "controller.requestCtxInterceptor"
	if iamRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing iam repo function")
	}
	if authTokenRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token repo function")
	}
	if serversRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing servers repo function")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	if ticket == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ticket")
	}
	// Authorization unary interceptor function to handle authorize per RPC call
	return func(interceptorCtx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
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

		interceptorCtx = auth.NewVerifierContext(interceptorCtx, iamRepoFn, authTokenRepoFn, serversRepoFn, kms, &requestInfo)

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
		handler grpc.UnaryHandler) (interface{}, error) {

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
