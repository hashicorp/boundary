// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

// a stack of funcs; each func will use handlers.RegisterUpstreamMessageHandler
// to register a handlers.UpstreamMessageHandler
var controllerRegisterUpstreamMessageHandlerFunctions []func(context.Context, *Controller) error

func init() {
	controllerGrpcServiceRegistrationFunctions = append(controllerGrpcServiceRegistrationFunctions,
		registerControllerServerCoordinationService,
		registerControllerSessionService,
		registerControllerMultihopService,
		registerControllerUpstreamMessageService,
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

	workerService := handlers.NewWorkerServiceServer(
		c.ServersRepoFn,
		c.WorkerAuthRepoStorageFn,
		c.SessionRepoFn,
		c.ConnectionRepoFn,
		c.downstreamWorkers,
		c.workerRoutingInfoUpdateTimes,
		c.kms,
		c.livenessTimeToStale,
		c.ControllerExtension,
	)
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

	workerService := handlers.NewWorkerServiceServer(
		c.ServersRepoFn,
		c.WorkerAuthRepoStorageFn,
		c.SessionRepoFn,
		c.ConnectionRepoFn,
		c.downstreamWorkers,
		c.workerRoutingInfoUpdateTimes,
		c.kms,
		c.livenessTimeToStale,
		c.ControllerExtension,
	)
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

func registerControllerUpstreamMessageService(ctx context.Context, c *Controller, server *grpc.Server) error {
	const op = "controller.registerControllerUpstreamMessageService"

	switch {
	case nodeenrollment.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case c == nil:
		return fmt.Errorf("%s: controller is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	workerAuthStorage, err := c.WorkerAuthRepoStorageFn()
	switch {
	case err != nil:
		return fmt.Errorf("%s: error fetching worker auth storage: %w", op, err)
	case workerAuthStorage == nil:
		return fmt.Errorf("%s: worker auth repository storage func is unset", op)
	}

	upstreamMsgService, err := handlers.NewControllerUpstreamMessageServiceServer(ctx, workerAuthStorage)
	if err != nil {
		return fmt.Errorf("%s: error creating upstream message service handler: %w", op, err)
	}
	pbs.RegisterUpstreamMessageServiceServer(server, upstreamMsgService)

	for _, registerHandlerFn := range controllerRegisterUpstreamMessageHandlerFunctions {
		if err := registerHandlerFn(ctx, c); err != nil {
			return fmt.Errorf("%s: error registering upstream message handler: %w", op, err)
		}
	}
	return nil
}
