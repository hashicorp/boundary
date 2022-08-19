package worker

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"google.golang.org/grpc"
)

var workerGrpcServiceRegistrationFunctions []func(context.Context, *Worker, *grpc.Server) error

func init() {
	workerGrpcServiceRegistrationFunctions = append(workerGrpcServiceRegistrationFunctions,
		registerWorkerStatusSessionService,
		registerWorkerMultihopService,
	)
}

func registerWorkerStatusSessionService(ctx context.Context, w *Worker, server *grpc.Server) error {
	const op = "worker.registerWorkerStatusSessionService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case w == nil:
		return fmt.Errorf("%s: worker is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	statusSessionService := NewWorkerProxyServiceServer(w.GrpcClientConn, w.controllerStatusConn)
	pbs.RegisterServerCoordinationServiceServer(server, statusSessionService)
	pbs.RegisterSessionServiceServer(server, statusSessionService)
	return nil
}

func registerWorkerMultihopService(ctx context.Context, w *Worker, server *grpc.Server) error {
	const op = "worker.registerWorkerMultihopService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case w == nil:
		return fmt.Errorf("%s: worker is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	multihopService, err := handlers.NewMultihopServiceServer(
		w.WorkerAuthStorage,
		false,
		w.controllerMultihopConn,
	)
	if err != nil {
		return fmt.Errorf("%s: error creating multihop service handler: %w", op, err)
	}
	multihop.RegisterMultihopServiceServer(server, multihopService)
	return nil
}
