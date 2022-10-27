package controller

import (
	"context"
	"math"
	"net"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const gatewayTarget = ""

type grpcServerListener interface {
	net.Listener
	Dial() (net.Conn, error)
}

func gatewayDialOptions(lis grpcServerListener) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	}
}

func newGrpcGatewayMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: handlers.JSONMarshaler(),
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler()),
		runtime.WithForwardResponseOption(handlers.OutgoingResponseFilter),
	)
}

// newGrpcServerListener will create an in-memory listener for the gRPC server.
func newGrpcServerListener() grpcServerListener {
	buffer := globals.DefaultMaxRequestSize // seems like a reasonable size for the ring buffer, but then happily change the size if more info becomes available
	return bufconn.Listen(int(buffer))
}

func newGrpcServer(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	kms *kms.Kms,
	eventer *event.Eventer,
) (*grpc.Server, string, error) {
	const op = "controller.newGrpcServer"
	ticket, err := db.NewPrivateId("gwticket")
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate gateway ticket"))
	}
	requestCtxInterceptor, err := requestCtxInterceptor(ctx, iamRepoFn, authTokenRepoFn, serversRepoFn, passwordAuthRepoFn, oidcAuthRepoFn, kms, ticket, eventer)
	if err != nil {
		return nil, "", err
	}
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				requestCtxInterceptor,                         // populated requestInfo from headers into the request ctx
				errorInterceptor(ctx),                         // convert domain and api errors into headers for the http proxy
				subtypes.AttributeTransformerInterceptor(ctx), // convert to/from generic attributes from/to subtype specific attributes
				auditRequestInterceptor(ctx),                  // before we get started, audit the request
				statusCodeInterceptor(ctx),                    // convert grpc codes into http status codes for the http proxy (can modify the resp)
				auditResponseInterceptor(ctx),                 // as we finish, audit the response
				grpc_recovery.UnaryServerInterceptor( // recover from panics with a grpc internal error
					grpc_recovery.WithRecoveryHandlerContext(recoveryHandler()),
				),
			),
		),
	), ticket, nil
}
