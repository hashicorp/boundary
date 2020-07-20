package workers

import (
	"context"

	"github.com/hashicorp/go-hclog"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
)

type workerServiceServer struct {
	logger hclog.Logger
}

func NewWorkerServiceServer(logger hclog.Logger) *workerServiceServer {
	return &workerServiceServer{
		logger: logger,
	}
}

func (ws *workerServiceServer) Authenticate(ctx context.Context, req *pbs.WorkerServiceAuthenticateRequest) (*pbs.WorkerServiceAuthenticateResponse, error) {
	return &pbs.WorkerServiceAuthenticateResponse{
		Success: true,
	}, nil
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	return &pbs.StatusResponse{}, nil
}
