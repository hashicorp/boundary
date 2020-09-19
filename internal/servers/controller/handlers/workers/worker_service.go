package workers

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerServiceServer struct {
	logger        hclog.Logger
	serversRepoFn common.ServersRepoFactory
	sessionRepoFn common.SessionRepoFactory
	updateTimes   *sync.Map
	kms           *kms.Kms
	jobCancelMap  *sync.Map
}

func NewWorkerServiceServer(
	logger hclog.Logger,
	serversRepoFn common.ServersRepoFactory,
	sessionRepoFn common.SessionRepoFactory,
	updateTimes *sync.Map,
	kms *kms.Kms) *workerServiceServer {
	return &workerServiceServer{
		logger:        logger,
		serversRepoFn: serversRepoFn,
		sessionRepoFn: sessionRepoFn,
		updateTimes:   updateTimes,
		kms:           kms,
		jobCancelMap:  new(sync.Map),
	}
}

var _ pbs.SessionServiceServer = &workerServiceServer{}
var _ pbs.ServerCoordinationServiceServer = &workerServiceServer{}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request from worker", "name", req.Worker.Name, "address", req.Worker.Address, "jobs", req.GetJobs())
	ws.updateTimes.Store(req.Worker.Name, time.Now())
	repo, err := ws.serversRepoFn()
	if err != nil {
		ws.logger.Error("error getting servers repo", "error", err)
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error aqcuiring repo to store worker status: %v", err)
	}
	req.Worker.Type = resource.Worker.String()
	controllers, _, err := repo.UpsertServer(ctx, req.Worker)
	if err != nil {
		ws.logger.Error("error storing worker status", "error", err)
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}
	ret := &pbs.StatusResponse{
		Controllers: controllers,
	}
	ws.jobCancelMap.Range(func(key, value interface{}) bool {
		ret.JobsRequests = append(ret.JobsRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				JobId: key.(string),
				Type:  pbs.Job_JOBTYPE_SESSION,
			},
			RequestType: 0,
		})
		return true
	})
	for _, j := range ret.JobsRequests {
		ws.jobCancelMap.Delete(j.GetJob().GetJobId())
	}
	return ret, nil
}

func (ws *workerServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	ws.logger.Trace("got validate session request from worker", "session_id", req.GetSessionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	sessionInfo, _, err := sessRepo.LookupSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error looking up session: %v", err)
	}
	if sessionInfo == nil {
		return nil, status.Error(codes.PermissionDenied, "Unknown session ID.")
	}

	resp := &pbs.LookupSessionResponse{
		Authorization: &targets.SessionAuthorizationData{
			SessionId:   sessionInfo.GetPublicId(),
			Certificate: sessionInfo.Certificate,
		},
		Version:                      sessionInfo.Version,
		TofuToken:                    base64.StdEncoding.EncodeToString(sessionInfo.TofuToken),
		Endpoint:                     sessionInfo.Endpoint,
		MaxSeconds:                   uint32(time.Until(sessionInfo.ExpirationTime.Timestamp.AsTime()).Seconds()),
		ConnectionIdleTimeoutSeconds: sessionInfo.ConnectionIdleTimeoutSeconds,
	}

	wrapper, err := ws.kms.GetWrapper(ctx, sessionInfo.ScopeId, kms.KeyPurposeSessions)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting sessions wrapper: %v", err)
	}

	// Derive the private key, which should match. Deriving on both ends allows
	// us to not store it in the DB.
	_, resp.Authorization.PrivateKey, err = session.DeriveED25519Key(wrapper, sessionInfo.UserId, sessionInfo.GetPublicId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error deriving session key: %v", err)
	}

	return resp, nil
}

func (ws *workerServiceServer) ActivateSession(ctx context.Context, req *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
	ws.logger.Trace("got activate session request from worker", "session_id", req.GetSessionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	sessionInfo, _, err := sessRepo.ActivateSession(
		ctx,
		req.GetSessionId(),
		req.GetVersion(),
		req.GetWorkerId(),
		resource.Worker.String(),
		[]byte(req.GetTofuToken()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error looking up session: %v", err)
	}
	if sessionInfo == nil {
		return nil, status.Error(codes.PermissionDenied, "Unknown session ID.")
	}

	return &pbs.ActivateSessionResponse{}, nil
}
