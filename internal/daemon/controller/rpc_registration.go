package controller

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"google.golang.org/grpc"
)

var controllerGrpcServiceRegistrationFunctions []func(context.Context, *Controller, *grpc.Server) error

func init() {
	controllerGrpcServiceRegistrationFunctions = append(controllerGrpcServiceRegistrationFunctions,
		registerControllerServerCoordinationService,
		registerControllerSessionService,
		registerControllerMultihopService,
	)
}

func registerControllerServerCoordinationService(ctx context.Context, c *Controller, server *grpc.Server) error {
	const op = "controller.registerControllerServerCoordinationService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case c == nil:
		return fmt.Errorf("%s: controller is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	workerService := handlers.NewWorkerServiceServer(c.ServersRepoFn, c.WorkerAuthRepoStorageFn,
		c.SessionRepoFn, c.ConnectionRepoFn, c.workerStatusUpdateTimes, c.kms, c.livenessTimeToStale)
	pbs.RegisterServerCoordinationServiceServer(server, workerService)
	return nil
}

func registerControllerSessionService(ctx context.Context, c *Controller, server *grpc.Server) error {
	const op = "controller.registerControllerSessionService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case c == nil:
		return fmt.Errorf("%s: controller is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	workerService := handlers.NewWorkerServiceServer(c.ServersRepoFn, c.WorkerAuthRepoStorageFn,
		c.SessionRepoFn, c.ConnectionRepoFn, c.workerStatusUpdateTimes, c.kms, c.livenessTimeToStale)
	pbs.RegisterSessionServiceServer(server, workerService)
	return nil
}

func registerControllerMultihopService(ctx context.Context, c *Controller, server *grpc.Server) error {
	const op = "controller.registerControllerMultihopService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case c == nil:
		return fmt.Errorf("%s: controller is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	workerAuthStorage, err := c.WorkerAuthRepoStorageFn()
	if err != nil {
		return fmt.Errorf("%s: error fetching worker auth storage: %w", op, err)
	}

	multihopService, err := handlers.NewMultihopServiceServer(
		workerAuthStorage,
		true,
		nil,
	)
	if err != nil {
		return fmt.Errorf("%s: error creating multihop service handler: %w", op, err)
	}
	multihop.RegisterMultihopServiceServer(server, multihopService)
	return nil
}
