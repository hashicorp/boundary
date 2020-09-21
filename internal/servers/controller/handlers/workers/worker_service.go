package workers

import (
	"context"
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

	// Happy path
	if len(req.GetJobs()) == 0 {
		return ret, nil
	}

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting session repo: %v", err)
	}

	for _, jobStatus := range req.GetJobs() {
		switch jobStatus.Job.GetType() {
		// Check for session cancellation
		case pbs.JOBTYPE_JOBTYPE_SESSION:
			si := jobStatus.GetJob().GetSessionInfo()
			if si == nil {
				return nil, status.Error(codes.Internal, "Error getting session info at status time")
			}
			switch si.Status {
			case pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELLING,
				pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED:
				// No need to see about canceling anything
				continue
			}
			sessionId := si.GetSessionId()
			sessionInfo, _, err := sessRepo.LookupSession(ctx, sessionId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Error looking up session with id %s: %v", sessionId, err)
			}
			if sessionInfo == nil {
				return nil, status.Errorf(codes.Internal, "Unknown session ID %s at status time.", sessionId)
			}
			if len(sessionInfo.States) == 0 {
				return nil, status.Error(codes.Internal, "Empty session states during lookup at status time.")
			}
			// If the session from the DB is in canceling status, and we're
			// here, it means the job is in pending or active; cancel it. If
			// it's in termianted status something went wrong and we're
			// mismatched, so ensure we cancel it also.
			currState := sessionInfo.States[0].Status
			switch currState {
			case session.StatusCancelling,
				session.StatusTerminated:
				ret.JobsRequests = append(ret.JobsRequests, &pbs.JobChangeRequest{
					Job: &pbs.Job{
						Type: pbs.JOBTYPE_JOBTYPE_SESSION,
						JobInfo: &pbs.Job_SessionInfo{
							SessionInfo: &pbs.SessionJobInfo{
								SessionId: sessionId,
								Status:    currState.ProtoVal(),
							},
						},
					},
					RequestType: pbs.CHANGETYPE_CHANGETYPE_CANCEL,
				})
			}
		}
	}
	return ret, nil
}

func (ws *workerServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	ws.logger.Trace("got validate session request from worker", "session_id", req.GetSessionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting session repo: %v", err)
	}

	sessionInfo, authzSummary, err := sessRepo.LookupSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error looking up session: %v", err)
	}
	if sessionInfo == nil {
		return nil, status.Error(codes.PermissionDenied, "Unknown session ID.")
	}
	if len(sessionInfo.States) == 0 {
		return nil, status.Error(codes.Internal, "Empty session states during lookup.")
	}

	resp := &pbs.LookupSessionResponse{
		Authorization: &targets.SessionAuthorizationData{
			SessionId:   sessionInfo.GetPublicId(),
			Certificate: sessionInfo.Certificate,
		},
		Status:          sessionInfo.States[0].Status.ProtoVal(),
		Version:         sessionInfo.Version,
		TofuToken:       string(sessionInfo.TofuToken),
		Endpoint:        sessionInfo.Endpoint,
		Expiration:      sessionInfo.ExpirationTime.Timestamp,
		ConnectionLimit: sessionInfo.ConnectionLimit,
		ConnectionsLeft: authzSummary.ConnectionLimit,
	}
	if resp.ConnectionsLeft != -1 {
		resp.ConnectionsLeft -= int32(authzSummary.CurrentConnectionCount)
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

	sessionInfo, sessionStates, err := sessRepo.ActivateSession(
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
	if len(sessionStates) == 0 {
		return nil, status.Error(codes.Internal, "Invalid session state in activate response.")
	}

	return &pbs.ActivateSessionResponse{
		Status: sessionStates[0].Status.ProtoVal(),
	}, nil
}

func (ws *workerServiceServer) AuthorizeConnection(ctx context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
	ws.logger.Trace("got authorize connection request from worker", "session_id", req.GetSessionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	connectionInfo, connStates, authzSummary, err := sessRepo.AuthorizeConnection(ctx, req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if connectionInfo == nil {
		return nil, status.Error(codes.Internal, "Invalid authorize connection response.")
	}
	if len(connStates) == 0 {
		return nil, status.Error(codes.Internal, "Invalid connection state in authorize response.")
	}

	ret := &pbs.AuthorizeConnectionResponse{
		ConnectionId:    connectionInfo.GetPublicId(),
		Status:          connStates[0].Status.ProtoVal(),
		ConnectionsLeft: authzSummary.ConnectionLimit,
	}
	if ret.ConnectionsLeft != -1 {
		ret.ConnectionsLeft -= int32(authzSummary.CurrentConnectionCount)
	}

	ws.logger.Trace("authorized connection", "session_id", req.GetSessionId(), "connection_id", ret.ConnectionId)

	return ret, nil
}

func (ws *workerServiceServer) ConnectSession(ctx context.Context, req *pbs.ConnectSessionRequest) (*pbs.ConnectSessionResponse, error) {
	ws.logger.Trace("got connection established information from worker", "connection_id", req.GetConnectionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	connectionInfo, connStates, err := sessRepo.ConnectSession(ctx, session.ConnectWith{
		ConnectionId:       req.GetConnectionId(),
		ClientTcpAddress:   req.GetClientTcpAddress(),
		ClientTcpPort:      req.GetClientTcpPort(),
		EndpointTcpAddress: req.GetEndpointTcpAddress(),
		EndpointTcpPort:    req.GetEndpointTcpPort(),
	})
	if err != nil {
		return nil, err
	}
	if connectionInfo == nil {
		return nil, status.Error(codes.Internal, "Invalid authorize connection response.")
	}

	ret := &pbs.ConnectSessionResponse{
		Status: connStates[0].Status.ProtoVal(),
	}

	return ret, nil
}
