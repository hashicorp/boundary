package workers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type workerServiceServer struct {
	pbs.UnimplementedServerCoordinationServiceServer
	pbs.UnimplementedSessionServiceServer

	serversRepoFn    common.ServersRepoFactory
	sessionRepoFn    common.SessionRepoFactory
	connectionRepoFn common.ConnectionRepoFactory
	updateTimes      *sync.Map
	kms              *kms.Kms
}

func NewWorkerServiceServer(
	serversRepoFn common.ServersRepoFactory,
	sessionRepoFn common.SessionRepoFactory,
	connectionRepoFn common.ConnectionRepoFactory,
	updateTimes *sync.Map,
	kms *kms.Kms,
) *workerServiceServer {
	return &workerServiceServer{
		serversRepoFn:    serversRepoFn,
		sessionRepoFn:    sessionRepoFn,
		connectionRepoFn: connectionRepoFn,
		updateTimes:      updateTimes,
		kms:              kms,
	}
}

var (
	_ pbs.SessionServiceServer            = &workerServiceServer{}
	_ pbs.ServerCoordinationServiceServer = &workerServiceServer{}
)

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	const op = "workers.(workerServiceServer).Status"
	// TODO: on the worker, if we get errors back from this repeatedly, do we
	// terminate all sessions since we can't know if they were canceled?
	ws.updateTimes.Store(req.Worker.PrivateId, time.Now())
	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting servers repo"))
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error acquiring repo to store worker status: %v", err)
	}
	sessRepo, err := ws.sessionRepoFn()
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting sessions repo"))
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}

	reqServer := req.GetWorker()
	// Convert API tags to storage tags
	workerTags := make([]*servers.Tag, 0, len(reqServer.Tags))
	for k, v := range reqServer.Tags {
		for _, val := range v.GetValues() {
			workerTags = append(workerTags, &servers.Tag{
				Key:   k,
				Value: val,
			})
		}
	}

	worker := servers.NewWorker(scope.Global.String(),
		servers.WithPublicId(reqServer.PrivateId),
		servers.WithAddress(reqServer.Address),
		servers.WithWorkerTags(workerTags...))
	controllers, _, err := serverRepo.UpsertWorker(ctx, worker, servers.WithUpdateTags(req.GetUpdateTags()))
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error storing worker status"))
		return &pbs.StatusResponse{}, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}

	responseControllers := []*servers.Server{}
	for _, c := range controllers {
		thisController := &servers.Server{
			PrivateId:  c.PrivateId,
			Address:    c.Address,
			CreateTime: c.CreateTime,
			UpdateTime: c.UpdateTime,
		}
		responseControllers = append(responseControllers, thisController)
	}
	ret := &pbs.StatusResponse{
		Controllers: responseControllers,
	}

	stateReport := make([]session.StateReport, 0, len(req.GetJobs()))

	for _, jobStatus := range req.GetJobs() {
		switch jobStatus.Job.GetType() {
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

			sr := session.StateReport{
				SessionId:     si.GetSessionId(),
				ConnectionIds: make([]string, 0, len(si.GetConnections())),
			}
			for _, conn := range si.GetConnections() {
				switch conn.Status {
				case pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
					pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
					sr.ConnectionIds = append(sr.ConnectionIds, conn.GetConnectionId())
				}
			}
			stateReport = append(stateReport, sr)
		}
	}

	notActive, err := session.WorkerStatusReport(ctx, sessRepo, connectionRepo, req.Worker.PrivateId, stateReport)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error comparing state of sessions for worker: %s: %v", req.Worker.PrivateId, err)
	}
	for _, na := range notActive {
		var connChanges []*pbs.Connection
		for _, connId := range na.ConnectionIds {
			connChanges = append(connChanges, &pbs.Connection{
				ConnectionId: connId,
				Status:       session.StatusClosed.ProtoVal(),
			})
		}
		ret.JobsRequests = append(ret.JobsRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_SESSION,
				JobInfo: &pbs.Job_SessionInfo{
					SessionInfo: &pbs.SessionJobInfo{
						SessionId:   na.SessionId,
						Status:      na.Status.ProtoVal(),
						Connections: connChanges,
					},
				},
			},
			RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
		})
	}

	return ret, nil
}

func (ws *workerServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	const op = "workers.(workerServiceServer).LookupSession"

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
			event.WriteError(ctx, op, errors.New("worker filter enabled for session but got no server ID from worker"))
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Did not receive server ID when looking up session but filtering is enabled: %v", err)
		}
		serversRepo, err := ws.serversRepoFn()
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error getting servers repo"))
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Error acquiring server repo when looking up session: %v", err)
		}
		workerTags, err := serversRepo.ListTagsForWorkers(ctx, []string{req.ServerId})
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error looking up tags for server", "server_id", req.ServerId))
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal, "Error looking up tags for server: %v", err)
		}
		// Build the map for filtering.
		tagMap := make(map[string][]string)
		for _, tags := range workerTags {
			for _, tag := range tags {
				tagMap[tag.Key] = append(tagMap[tag.Key], tag.Value)
				// We don't need to reinsert after the fact because maps are
				// reference types, so we don't need to re-insert into tagMap
			}
		}

		// Create the evaluator
		eval, err := bexpr.CreateEvaluator(sessionInfo.WorkerFilter)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error creating worker filter evaluator", "server_id", req.ServerId))
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

	creds, err := sessRepo.ListSessionCredentials(ctx, sessionInfo.ScopeId, sessionInfo.PublicId)
	if err != nil {
		return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal,
			fmt.Sprintf("Error retrieving session credentials: %s", err))
	}
	var workerCreds []*pbs.Credential
	for _, c := range creds {
		m := &pbs.Credential{}
		err = proto.Unmarshal(c, m)
		if err != nil {
			return &pbs.LookupSessionResponse{}, status.Errorf(codes.Internal,
				fmt.Sprintf("Error unmarshaling credentials: %s", err))
		}
		workerCreds = append(workerCreds, m)
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
		Credentials:     workerCreds,
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
	_, resp.Authorization.PrivateKey, err = session.DeriveED25519Key(ctx, wrapper, sessionInfo.UserId, sessionInfo.GetPublicId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error deriving session key: %v", err)
	}

	return resp, nil
}

func (ws *workerServiceServer) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	const op = "workers.(workerServiceServer).CancelSession"

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
	const op = "workers.(workerServiceServer).ActivateSession"

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	sessionInfo, sessionStates, err := sessRepo.ActivateSession(ctx, req.GetSessionId(), req.GetVersion(), []byte(req.GetTofuToken()))
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
	const op = "workers.(workerServiceServer).AuthorizeConnection"
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	sessionRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	connectionInfo, connStates, authzSummary, err := session.AuthorizeConnection(ctx, sessionRepo, connectionRepo, req.GetSessionId(), req.GetWorkerId())
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

	return ret, nil
}

func (ws *workerServiceServer) ConnectConnection(ctx context.Context, req *pbs.ConnectConnectionRequest) (*pbs.ConnectConnectionResponse, error) {
	const op = "workers.(workerServiceServer).ConnectConnection"
	connRepo, err := ws.connectionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	connectionInfo, connStates, err := connRepo.ConnectConnection(ctx, session.ConnectWith{
		ConnectionId:       req.GetConnectionId(),
		ClientTcpAddress:   req.GetClientTcpAddress(),
		ClientTcpPort:      req.GetClientTcpPort(),
		EndpointTcpAddress: req.GetEndpointTcpAddress(),
		EndpointTcpPort:    req.GetEndpointTcpPort(),
		UserClientIp:       req.GetUserClientIp(),
	})
	if err != nil {
		return nil, err
	}
	if connectionInfo == nil {
		return nil, status.Error(codes.Internal, "Invalid connect connection response.")
	}

	return &pbs.ConnectConnectionResponse{
		Status: connStates[0].Status.ProtoVal(),
	}, nil
}

func (ws *workerServiceServer) CloseConnection(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	const op = "workers.(workerServiceServer).CloseConnection"
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
	connRepo, err := ws.connectionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting connection repo: %v", err)
	}

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting session repo: %v", err)
	}

	closeInfos, err := session.CloseConnections(ctx, sessRepo, connRepo, closeWiths)
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

	ret := &pbs.CloseConnectionResponse{
		CloseResponseData: closeData,
	}

	return ret, nil
}
