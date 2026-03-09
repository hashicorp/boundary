// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"google.golang.org/grpc"
)

var workerGrpcServiceRegistrationFunctions []func(context.Context, *Worker, *grpc.Server) error

func init() {
	workerGrpcServiceRegistrationFunctions = append(workerGrpcServiceRegistrationFunctions,
		registerWorkerStatusSessionService,
		registerWorkerMultihopService,
		registerWorkerUpstreamMessageService,
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

	statusSessionService := NewWorkerProxyServiceServer(w.GrpcClientConn.Load())
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

func registerWorkerUpstreamMessageService(ctx context.Context, w *Worker, server *grpc.Server) error {
	const op = "worker.registerWorkerUpstreamMessageService"

	switch {
	case util.IsNil(ctx):
		return fmt.Errorf("%s: context is nil", op)
	case w == nil:
		return fmt.Errorf("%s: controller is nil", op)
	case server == nil:
		return fmt.Errorf("%s: server is nil", op)
	}

	clientProducer := w.controllerUpstreamMsgConn.Load()
	switch {
	case clientProducer == nil:
		return fmt.Errorf("%s: upstream message service client producer is unset", op)
	}

	upstreamMsgService, err := handlers.NewWorkerUpstreamMessageServiceServer(ctx, *clientProducer)
	if err != nil {
		return fmt.Errorf("%s: error creating multihop service handler: %w", op, err)
	}
	pbs.RegisterUpstreamMessageServiceServer(server, upstreamMsgService)
	return nil
}
