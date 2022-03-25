package controller

import (
	"context"
	"math"
	"net"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/internal/marshaler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// newGatewayListener will create an in-memory listener
func newGatewayListener() (gatewayListener, string) {
	buffer := globals.DefaultMaxRequestSize // seems like a reasonable size for the ring buffer, but then happily change the size if more info becomes available
	return bufconn.Listen(int(buffer)), ""
}

const gatewayTarget = ""

type gatewayListener interface {
	net.Listener
	Dial() (net.Conn, error)
}

func gatewayDialOptions(lis gatewayListener) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	}
}

func newGatewayMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: marshaler.New(),
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler()),
		runtime.WithForwardResponseOption(handlers.OutgoingResponseFilter),
	)
}

func newGatewayServer(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	kms *kms.Kms,
	eventer *event.Eventer,
) (*grpc.Server, string, error) {
	const op = "controller.newGatewayServer"
	ticket, err := db.NewPrivateId("gwticket")
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate gateway ticket"))
	}
	requestCtxInterceptor, err := requestCtxInterceptor(ctx, iamRepoFn, authTokenRepoFn, serversRepoFn, kms, ticket, eventer)
	if err != nil {
		return nil, "", err
	}
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				requestCtxInterceptor,         // populated requestInfo from headers into the request ctx
				auditRequestInterceptor(ctx),  // before we get started, audit the request
				errorInterceptor(ctx),         // convert domain and api errors into headers for the http proxy
				statusCodeInterceptor(ctx),    // convert grpc codes into http status codes for the http proxy (can modify the resp)
				auditResponseInterceptor(ctx), // as we finish, audit the response
				grpc_recovery.UnaryServerInterceptor( // recover from panics with a grpc internal error
					grpc_recovery.WithRecoveryHandlerContext(recoveryHandler()),
				),
			),
		),
	), ticket, nil
}
