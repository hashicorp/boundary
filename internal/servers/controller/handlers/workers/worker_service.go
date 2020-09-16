package workers

import (
	"context"
	"sync"
	"time"

	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
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
	logger       hclog.Logger
	repoFn       common.ServersRepoFactory
	updateTimes  *sync.Map
	kms          *kms.Kms
	sessRepoFn   common.SessionRepoFactory
	jobCancelMap *sync.Map
}

func NewWorkerServiceServer(logger hclog.Logger, sessRepoFn common.SessionRepoFactory, servRepoFn common.ServersRepoFactory, updateTimes *sync.Map, kms *kms.Kms, jobMap *sync.Map) *workerServiceServer {
	return &workerServiceServer{
		logger:       logger,
		repoFn:       servRepoFn,
		updateTimes:  updateTimes,
		kms:          kms,
		sessRepoFn:   sessRepoFn,
		jobCancelMap: new(sync.Map),
	}
}

var _ pbs.SessionManagementServiceServer = &workerServiceServer{}
var _ pbs.ServerCoordinationServiceServer = &workerServiceServer{}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request from worker", "name", req.Worker.Name, "address", req.Worker.Address, "jobs", req.GetJobs())
	ws.updateTimes.Store(req.Worker.Name, time.Now())
	repo, err := ws.repoFn()
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

func (ws *workerServiceServer) GetSessionCreds(ctx context.Context, req *pbs.GetSessionCredsRequest) (*pbs.GetSessionCredsResponse, error) {
	ws.logger.Trace("got validate session request from worker", "job_id", req.GetId())

	// Look up the session creds
	repo, err := ws.sessRepoFn()
	if err != nil {
		return nil, err
	}
	sess, _, err := repo.LookupSession(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, status.Errorf(codes.NotFound, "Unable to find session creds for session %q", req.GetId())
	}

	wrapper, err := ws.kms.GetWrapper(ctx, sess.ScopeId, kms.KeyPurposeSessions)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting sessions wrapper: %v", err)
	}

	// Derive the private key, which should match. Deriving on both ends allows
	// us to not store it in the DB.
	_, privKey, err := session.DeriveED25519Key(wrapper, sess.UserId, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error deriving session key: %v", err)
	}

	sessCreds := &pb.SessionCreds{}

	if sess.ExpirationTime.GetTimestamp().GetSeconds() > 0 {
		timeDiff := time.Until(sess.ExpirationTime.GetTimestamp().AsTime())
		if timeDiff < 0 {
			return nil, status.Errorf(codes.OutOfRange, "Session has already expired")
		}
		defer func() {
			time.AfterFunc(timeDiff, func() {
				ws.jobCancelMap.Store(req.GetId(), true)
			})
		}()
	}

	sessCreds.PrivateKey = privKey
	return &pbs.GetSessionCredsResponse{SessionCreds: sessCreds}, nil
}
