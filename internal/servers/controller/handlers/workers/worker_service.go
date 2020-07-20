package workers

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/coocood/freecache"
	"github.com/hashicorp/go-hclog"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
)

type workerServiceServer struct {
	logger    hclog.Logger
	authCache *freecache.Cache
}

func NewWorkerServiceServer(logger hclog.Logger, authCache *freecache.Cache) *workerServiceServer {
	return &workerServiceServer{
		logger:    logger,
		authCache: authCache,
	}
}

func (ws *workerServiceServer) Authenticate(ctx context.Context, req *pbs.WorkerServiceAuthenticateRequest) (*pbs.WorkerServiceAuthenticateResponse, error) {
	nonce, err := ws.authCache.Get([]byte(req.GetName()))
	if err != nil {
		ws.logger.Error("unable to look up nonce for incoming worker", "error", err)
		return nil, errors.New("forbidden")
	}
	incomingNonce := []byte(req.ConnectionNonce)

	if subtle.ConstantTimeCompare(nonce, incomingNonce) != 1 {
		ws.logger.Error("nonce mismatch for incoming worker", "name", req.Name)
		return nil, errors.New("forbidden")
	}

	return &pbs.WorkerServiceAuthenticateResponse{
		Success: true,
	}, nil
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	return &pbs.StatusResponse{}, nil
}
