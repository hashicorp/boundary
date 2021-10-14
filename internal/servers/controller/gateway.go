package controller

import (
	"context"
	"math"
	"net"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
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
			Marshaler: handlers.JSONMarshaler(),
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler()),
		runtime.WithForwardResponseOption(handlers.OutgoingResponseFilter),
	)
}

func newGatewayServer(ctx context.Context, iamRepoFn common.IamRepoFactory, authTokenRepoFn common.AuthTokenRepoFactory, serversRepoFn common.ServersRepoFactory, kms *kms.Kms) (*grpc.Server, string, error) {
	const op = "controller.newGatewayServer"
	ticket, err := db.NewPrivateId("gwticket")
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate gateway ticket"))
	}
	requestCtxInterceptor, err := requestCtxInterceptor(ctx, iamRepoFn, authTokenRepoFn, serversRepoFn, kms, ticket)
	if err != nil {
		return nil, "", err
	}
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(requestCtxInterceptor, errorInterceptor(ctx), statusCodeInterceptor(ctx))),
	), ticket, nil
}
