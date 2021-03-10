package workers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-bexpr"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerServiceServer struct {
	pbs.UnimplementedServerCoordinationServiceServer
	pbs.UnimplementedSessionServiceServer

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

var (
	_ pbs.SessionServiceServer            = &workerServiceServer{}
	_ pbs.ServerCoordinationServiceServer = &workerServiceServer{}
)

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	ws.logger.Trace("got status request from worker", "name", req.Worker.PrivateId, "address", req.Worker.Address, "jobs", req.GetJobs())
	ws.updateTimes.Store(req.Worker.PrivateId, time.Now())
	repo, err := ws.serversRepoFn()
	if err != nil {
		ws.logger.Error("error getting servers repo", "error", err)
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error aqcuiring repo to store worker status: %v", err)
	}
	req.Worker.Type = resource.Worker.String()
	controllers, _, err := repo.UpsertServer(ctx, req.Worker, servers.WithUpdateTags(req.GetUpdateTags()))
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
		// Check for session cancelation
		case pbs.JOBTYPE_JOBTYPE_SESSION:
			si := jobStatus.GetJob().GetSessionInfo()
			if si == nil {
				return nil, status.Error(codes.Internal, "Error getting session info at status time")
			}
			switch si.Status {
			case pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
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
			if currState.ProtoVal() != si.Status {
				switch currState {
				case session.StatusCanceling,
					session.StatusTerminated:
					// If we're here the job is pending or active so we do want
					// to actually send a change request
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
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					})
				}
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

	if sessionInfo.WorkerFilter != "" {
		if req.ServerId == "" {
			ws.logger.Error("worker filter enabled for session but got no server ID from worker")
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Did not receive server ID when looking up session but filtering is enabled: %v", err)
		}
		serversRepo, err := ws.serversRepoFn()
		if err != nil {
			ws.logger.Error("error getting servers repo", "error", err)
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Error acquiring server repo when looking up session: %v", err)
		}
		tags, err := serversRepo.ListTagsForServers(ctx, []string{req.ServerId})
		if err != nil {
			ws.logger.Error("error looking up tags for server", "error", err, "server_id", req.ServerId)
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Error looking up tags for server: %v", err)
		}
		// Build the map for filtering.
		tagMap := make(map[string][]string)
		for _, tag := range tags {
			tagMap[tag.Key] = append(tagMap[tag.Key], tag.Value)
			// We don't need to reinsert after the fact because maps are
			// reference types, so we don't need to re-insert into tagMap
		}

		// Create the evaluator
		eval, err := bexpr.CreateEvaluator(sessionInfo.WorkerFilter)
		if err != nil {
			ws.logger.Error("error creating worker filter evaluator", "error", err, "server_id", req.ServerId)
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Error creating worker filter evaluator: %v", err)
		}
		filterInput := map[string]interface{}{
			"name": req.ServerId,
			"tags": tagMap,
		}
		ok, err := eval.Evaluate(filterInput)
		if err != nil {
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal,
				fmt.Sprintf("Worker filter expression evaluation resulted in error: %s", err))
		}
		if !ok {
			return nil, handlers.ApiErrorWithCodeAndMessage(
				codes.FailedPrecondition,
				"Worker filter expression precludes this worker from serving this session")
		}
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
		HostId:          sessionInfo.HostId,
		HostSetId:       sessionInfo.HostSetId,
		TargetId:        sessionInfo.TargetId,
		UserId:          sessionInfo.UserId,
	}
	if resp.ConnectionsLeft != -1 {
		resp.ConnectionsLeft -= int32(authzSummary.CurrentConnectionCount)
	}

	wrapper, err := ws.kms.GetWrapper(ctx, sessionInfo.ScopeId, kms.KeyPurposeSessions, kms.WithKeyId(sessionInfo.KeyId))
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

func (ws *workerServiceServer) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	ws.logger.Trace("got cancel session request from worker", "session_id", req.GetSessionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	ses, _, err := sessRepo.LookupSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, err
	}

	ses, err = sessRepo.CancelSession(ctx, req.GetSessionId(), ses.Version)
	if err != nil {
		return nil, err
	}

	return &pbs.CancelSessionResponse{
		Status: ses.States[0].Status.ProtoVal(),
	}, nil
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

	ws.logger.Info("session activated",
		"session_id", sessionInfo.PublicId,
		"target_id", sessionInfo.TargetId,
		"user_id", sessionInfo.UserId,
		"host_set_id", sessionInfo.HostSetId,
		"host_id", sessionInfo.HostId)

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

	ws.logger.Info("authorized connection",
		"session_id", req.GetSessionId(),
		"connection_id", ret.ConnectionId,
		"connections_left", ret.ConnectionsLeft)

	return ret, nil
}

func (ws *workerServiceServer) ConnectConnection(ctx context.Context, req *pbs.ConnectConnectionRequest) (*pbs.ConnectConnectionResponse, error) {
	ws.logger.Trace("got connection established information from worker", "connection_id", req.GetConnectionId())

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	connectionInfo, connStates, err := sessRepo.ConnectConnection(ctx, session.ConnectWith{
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
		return nil, status.Error(codes.Internal, "Invalid connect connection response.")
	}

	ret := &pbs.ConnectConnectionResponse{
		Status: connStates[0].Status.ProtoVal(),
	}

	loggerPairs := []interface{}{
		"session_id", connectionInfo.SessionId,
		"connection_id", req.ConnectionId,
		"client_tcp_address", req.ClientTcpAddress,
		"client_tcp_port", req.ClientTcpPort,
	}
	switch req.GetType() {
	case "tcp":
		loggerPairs = append(loggerPairs,
			"endpoint_tcp_address", connectionInfo.EndpointTcpAddress,
			"endpoint_tcp_port", connectionInfo.EndpointTcpPort,
		)
	}

	ws.logger.Info("connection established", loggerPairs...)

	return ret, nil
}

func (ws *workerServiceServer) CloseConnection(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	numCloses := len(req.GetCloseRequestData())
	if numCloses == 0 {
		return &pbs.CloseConnectionResponse{}, nil
	}

	closeWiths := make([]session.CloseWith, 0, numCloses)
	closeIds := make([]string, 0, numCloses)

	for _, v := range req.GetCloseRequestData() {
		closeIds = append(closeIds, v.GetConnectionId())
		closeWiths = append(closeWiths, session.CloseWith{
			ConnectionId: v.GetConnectionId(),
			BytesUp:      v.GetBytesUp(),
			BytesDown:    v.GetBytesDown(),
			ClosedReason: session.ClosedReason(v.GetReason()),
		})
	}
	ws.logger.Trace("got connection close information from worker", "connection_ids", closeIds)

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	closeInfos, err := sessRepo.CloseConnections(ctx, closeWiths)
	if err != nil {
		return nil, err
	}
	if closeInfos == nil {
		return nil, status.Error(codes.Internal, "Invalid close connection response.")
	}

	closeData := make([]*pbs.CloseConnectionResponseData, 0, numCloses)
	for _, v := range closeInfos {
		if v.Connection == nil {
			return nil, status.Errorf(codes.Internal, "No connection found while closing one of the connection IDs: %v", closeIds)
		}
		if len(v.ConnectionStates) == 0 {
			return nil, status.Errorf(codes.Internal, "No connection states found while closing one of the connection IDs: %v", closeIds)
		}
		closeData = append(closeData, &pbs.CloseConnectionResponseData{
			ConnectionId: v.Connection.GetPublicId(),
			Status:       v.ConnectionStates[0].Status.ProtoVal(),
		})
	}

	for _, v := range req.GetCloseRequestData() {
		ws.logger.Info("connection closed", "connection_id", v.ConnectionId)
	}

	ret := &pbs.CloseConnectionResponse{
		CloseResponseData: closeData,
	}

	return ret, nil
}
