package workers

import (
	"context"
	"sync"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/sessions"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerServiceServer struct {
	logger      hclog.Logger
	repoFn      common.ServersRepoFactory
	updateTimes *sync.Map
	kms         *kms.Kms
	jobMap      *sync.Map
}

func NewWorkerServiceServer(logger hclog.Logger, repoFn common.ServersRepoFactory, updateTimes *sync.Map, kms *kms.Kms, jobMap *sync.Map) *workerServiceServer {
	return &workerServiceServer{
		logger:      logger,
		repoFn:      repoFn,
		updateTimes: updateTimes,
		kms:         kms,
		jobMap:      jobMap,
	}
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request from worker", "name", req.Worker.Name, "address", req.Worker.Address)
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

func (ws *workerServiceServer) ValidateSession(ctx context.Context, req *pbs.ValidateSessionRequest) (*pbs.ValidateSessionResponse, error) {
	ws.logger.Trace("got validate session request from worker", "job_id", req.GetId())

	// Look up the job info
	storedSessionInfo, loaded := ws.jobMap.LoadAndDelete(req.GetId())
	if !loaded {
		return &pbs.ValidateSessionResponse{}, status.Errorf(codes.PermissionDenied, "Unknown job ID: %v", req.GetId())
	}
	sessionInfo := storedSessionInfo.(*pbs.ValidateSessionResponse)

	wrapper, err := ws.kms.GetWrapper(ctx, sessionInfo.ScopeId, kms.KeyPurposeSessions)
	if err != nil {
		return &pbs.ValidateSessionResponse{}, status.Errorf(codes.Internal, "Error getting sessions wrapper: %v", err)
	}

	// Derive the private key, which should match. Deriving on both ends allows
	// us to not store it in the DB.
	_, privKey, err := sessions.DeriveED25519Key(wrapper, sessionInfo.GetUserId(), req.GetId())
	if err != nil {
		return &pbs.ValidateSessionResponse{}, status.Errorf(codes.Internal, "Error deriving session key: %v", err)
	}

	sessionInfo.PrivateKey = privKey
	return sessionInfo, nil
}
