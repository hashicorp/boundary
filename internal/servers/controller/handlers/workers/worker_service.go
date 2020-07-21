package workers

import (
	"context"

	"github.com/hashicorp/go-hclog"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/patrickmn/go-cache"
)

type workerServiceServer struct {
	logger    hclog.Logger
	authCache *cache.Cache
}

func NewWorkerServiceServer(logger hclog.Logger, authCache *cache.Cache) *workerServiceServer {
	return &workerServiceServer{
		logger:    logger,
		authCache: authCache,
	}
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request", "name", req.Name)
	return &pbs.StatusResponse{}, nil
}
