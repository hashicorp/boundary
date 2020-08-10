package workers

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/common"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerServiceServer struct {
	logger      hclog.Logger
	repoFn      common.ServersRepoFactory
	updateTimes *sync.Map
}

func NewWorkerServiceServer(logger hclog.Logger, repoFn common.ServersRepoFactory, updateTimes *sync.Map) *workerServiceServer {
	return &workerServiceServer{
		logger:      logger,
		repoFn:      repoFn,
		updateTimes: updateTimes,
	}
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request from worker", "name", req.Worker.Name)
	ws.updateTimes.Store(req.Worker.Name, time.Now())
	repo, err := ws.repoFn()
	if err != nil {
		ws.logger.Error("error getting servers repo", "error", err)
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error aqcuiring repo to store worker status: %v", err)
	}
	req.Worker.Type = resource.Worker.String()
	controllers, _, err := repo.Upsert(ctx, req.Worker)
	if err != nil {
		ws.logger.Error("error storing worker status", "error", err)
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}
	return &pbs.StatusResponse{
		Controllers: controllers,
	}, nil
}
