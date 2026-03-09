// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/downstream"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type workerServiceServer struct {
	pbs.UnsafeServerCoordinationServiceServer
	pbs.UnsafeSessionServiceServer

	serversRepoFn       common.ServersRepoFactory
	workerAuthRepoFn    common.WorkerAuthRepoStorageFactory
	sessionRepoFn       session.RepositoryFactory
	connectionRepoFn    common.ConnectionRepoFactory
	downstreams         downstream.Graph
	updateTimes         *sync.Map
	kms                 *kms.Kms
	livenessTimeToStale *atomic.Int64
	controllerExt       intglobals.ControllerExtension
}

var (
	_ pbs.SessionServiceServer            = &workerServiceServer{}
	_ pbs.ServerCoordinationServiceServer = &workerServiceServer{}

	workerFilterSelectionFn = egressFilterSelector
	// connectionRouteFn returns a route to the egress worker.  If the requester
	// is the egress worker a route of length 1 is returned. A route of
	// length 0 is never returned unless there is an error.
	connectionRouteFn = singleHopConnectionRoute

	// getProtocolContext populates the protocol specific context fields
	// depending on the protocol used to for the boundary connection. Defaults
	// to noProtocolContext since tcp connections are the only protocol schemes
	// available in OSS and are a straight forward proxy with no additional
	// fields needed.
	getProtocolContext = noProtocolContext

	// updateWorkerStorageBucketCredentialStatesFn will update the worker storage bucket
	// credential state.
	updateWorkerStorageBucketCredentialStatesFn = updateWorkerStorageBucketCredentialStates
)

// singleHopConnectionRoute returns a route consisting of the singlehop worker (the root worker id)
func singleHopConnectionRoute(_ context.Context, w *server.Worker, _ *session.Session, _ *server.Repository, _ downstream.Graph) ([]string, error) {
	return []string{w.GetPublicId()}, nil
}

func NewWorkerServiceServer(
	serversRepoFn common.ServersRepoFactory,
	workerAuthRepoFn common.WorkerAuthRepoStorageFactory,
	sessionRepoFn session.RepositoryFactory,
	connectionRepoFn common.ConnectionRepoFactory,
	downstreams downstream.Graph,
	updateTimes *sync.Map,
	kms *kms.Kms,
	livenessTimeToStale *atomic.Int64,
	controllerExt intglobals.ControllerExtension,
) *workerServiceServer {
	return &workerServiceServer{
		serversRepoFn:       serversRepoFn,
		workerAuthRepoFn:    workerAuthRepoFn,
		sessionRepoFn:       sessionRepoFn,
		connectionRepoFn:    connectionRepoFn,
		downstreams:         downstreams,
		updateTimes:         updateTimes,
		kms:                 kms,
		livenessTimeToStale: livenessTimeToStale,
		controllerExt:       controllerExt,
	}
}

func (ws *workerServiceServer) Statistics(ctx context.Context, req *pbs.StatisticsRequest) (*pbs.StatisticsResponse, error) {
	const op = "workers.(workerServiceServer).Statistics"
	workerId := req.GetWorkerId()
	if workerId == "" {
		return &pbs.StatisticsResponse{}, status.Error(codes.InvalidArgument, "worker id is empty")
	}
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting connection repo"))
		return &pbs.StatisticsResponse{}, status.Errorf(codes.Internal, "Error acquiring connection repo: %v", err)
	}
	connectionStats := []*session.Connection{}
	for _, s := range req.GetSessions() {
		sessionId := s.GetSessionId()
		if sessionId == "" {
			return &pbs.StatisticsResponse{}, status.Error(codes.InvalidArgument, "session id is empty")
		}
		for _, c := range s.Connections {
			connectionId := c.GetConnectionId()
			if connectionId == "" {
				return &pbs.StatisticsResponse{}, status.Error(codes.InvalidArgument, "connection id is empty")
			}
			switch c.Status {
			case pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED, pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
				connectionStats = append(connectionStats, &session.Connection{
					PublicId:  c.GetConnectionId(),
					BytesUp:   c.GetBytesUp(),
					BytesDown: c.GetBytesDown(),
				})
			default:
				// Other statuses are not included in the stats sent to the domain
			}
		}
	}
	updateBytesErr := session.UpdateConnectionBytesUpDown(ctx, connectionRepo, connectionStats)
	_, closeOrphanedErr := session.CloseOrphanedConnections(ctx, connectionRepo, workerId, connectionStats)
	sessionErrs := stderrors.Join(updateBytesErr, closeOrphanedErr)
	if sessionErrs != nil {
		return &pbs.StatisticsResponse{}, errors.Wrap(ctx, sessionErrs, op)
	}
	return &pbs.StatisticsResponse{}, nil
}

func (ws *workerServiceServer) SessionInfo(ctx context.Context, req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
	const op = "workers.(workerServiceServer).SessionInfo"
	workerId := req.GetWorkerId()
	if workerId == "" {
		return &pbs.SessionInfoResponse{}, status.Error(codes.InvalidArgument, "worker id is empty")
	}
	sessionTypeCache := map[string]pbs.SessionType{}
	var recordedSessionIds []string
	var ingressedSessionIds []string
	for _, s := range req.GetSessions() {
		sessionId := s.GetSessionId()
		sessionStatus := s.GetSessionStatus()
		sessionType := s.GetSessionType()
		switch sessionType {
		case pbs.SessionType_SESSION_TYPE_UNSPECIFIED:
			return &pbs.SessionInfoResponse{}, status.Errorf(codes.InvalidArgument, "unspecified session type")
		case pbs.SessionType_SESSION_TYPE_INGRESSED:
			if sessionStatus == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING || sessionStatus == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED {
				// No need to see about canceling anything
				continue
			}
			sessionTypeCache[sessionId] = sessionType
			ingressedSessionIds = append(ingressedSessionIds, sessionId)
		case pbs.SessionType_SESSION_TYPE_RECORDED:
			if sessionStatus == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING || sessionStatus == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED {
				// No need to see about canceling anything
				continue
			}
			sessionTypeCache[sessionId] = sessionType
			recordedSessionIds = append(recordedSessionIds, sessionId)
		default:
			return &pbs.SessionInfoResponse{}, status.Errorf(codes.InvalidArgument, "unknown session type: %q", s.GetSessionType().String())
		}
	}

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		return &pbs.SessionInfoResponse{}, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}

	result := &pbs.SessionInfoResponse{}
	nonActiveSessions, err := sessRepo.CheckIfNotActive(ctx, append(ingressedSessionIds, recordedSessionIds...))
	if err != nil {
		return &pbs.SessionInfoResponse{}, status.Errorf(codes.Internal,
			"Error checking if sessions are no longer active: %v", err)
	}
	for _, s := range nonActiveSessions {
		switch sessionTypeCache[s.SessionId] {
		case pbs.SessionType_SESSION_TYPE_INGRESSED:
			var connChanges []*pbs.Connection
			for _, conn := range s.Connections {
				connChanges = append(connChanges, &pbs.Connection{
					ConnectionId: conn.GetPublicId(),
					Status:       session.StatusClosed.ProtoVal(),
				})
			}
			result.NonActiveSessions = append(result.NonActiveSessions, &pbs.Session{
				SessionId:     s.SessionId,
				SessionStatus: s.Status.ProtoVal(),
				SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
				Connections:   connChanges,
			})
		case pbs.SessionType_SESSION_TYPE_RECORDED:
			result.NonActiveSessions = append(result.NonActiveSessions, &pbs.Session{
				SessionId:     s.SessionId,
				SessionStatus: s.Status.ProtoVal(),
				SessionType:   pbs.SessionType_SESSION_TYPE_RECORDED,
			})
		default:
			return &pbs.SessionInfoResponse{}, status.Errorf(codes.Internal,
				"unknown session type found for non active session: %q", s.SessionId)
		}
	}

	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		return &pbs.SessionInfoResponse{}, status.Errorf(codes.Internal, "Error acquiring repo to upsert session info status time: %v", err)
	}
	err = serverRepo.UpsertSessionInfo(ctx, workerId)
	if err != nil {
		return &pbs.SessionInfoResponse{}, status.Errorf(codes.Internal, "Error updating the latest status time for the server session info: %v", err)
	}
	return result, nil
}

// Status is the deprecated method for worker status updates.
// This is safe to remove after the release of Boundary v0.20.0.
func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	const op = "workers.(workerServiceServer).Status"

	wStat := req.GetWorkerStatus()
	if wStat == nil {
		return nil, status.Error(codes.InvalidArgument, "Worker sent nil status.")
	}
	switch {
	case wStat.GetName() == "" && wStat.GetKeyId() == "":
		return nil, status.Error(codes.InvalidArgument, "Name and keyId are not set in the request; one is required.")
	case wStat.GetAddress() == "":
		return nil, status.Error(codes.InvalidArgument, "Address is not set but is required.")
	}
	// This Store call is currently only for testing purposes
	ws.updateTimes.Store(wStat.GetName(), time.Now())

	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting server repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to store worker status: %v", err)
	}

	// Convert API tags to storage tags
	wTags := wStat.GetTags()
	workerTags := make([]*server.Tag, 0, len(wTags))
	for _, v := range wTags {
		workerTags = append(workerTags, &server.Tag{
			Key:   v.GetKey(),
			Value: v.GetValue(),
		})
	}

	if wStat.OperationalState == "" {
		// If this is an older worker (pre 0.11), it will not have ReleaseVersion and we'll default to active.
		// Otherwise, default to Unknown.
		if wStat.ReleaseVersion == "" {
			wStat.OperationalState = server.ActiveOperationalState.String()
		} else {
			wStat.OperationalState = server.UnknownOperationalState.String()
		}
	}

	if wStat.LocalStorageState == "" {
		// If this is an older worker (pre 0.15), it will not have LocalStorageState as part of it's status
		// so we'll default to unknown.
		wStat.LocalStorageState = server.UnknownLocalStorageState.String()
	}

	wConf := server.NewWorker(scope.Global.String(),
		server.WithName(wStat.GetName()),
		server.WithDescription(wStat.GetDescription()),
		server.WithAddress(wStat.GetAddress()),
		server.WithWorkerTags(workerTags...),
		server.WithReleaseVersion(wStat.ReleaseVersion),
		server.WithOperationalState(wStat.OperationalState),
		server.WithLocalStorageState(wStat.LocalStorageState))
	opts := []server.Option{server.WithUpdateTags(req.GetUpdateTags())}
	if wStat.GetPublicId() != "" {
		opts = append(opts, server.WithPublicId(wStat.GetPublicId()))
	}
	if wStat.GetKeyId() != "" {
		opts = append(opts, server.WithKeyId(wStat.GetKeyId()))
	}
	workerId, err := serverRepo.UpsertWorkerStatus(ctx, wConf, opts...)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error storing worker status"))
		return nil, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}

	// update storage states
	if sbcStates := wStat.GetStorageBucketCredentialStates(); sbcStates != nil && workerId != "" {
		updateWorkerStorageBucketCredentialStatesFn(ctx, serverRepo, workerId, sbcStates)
	}

	controllers, err := serverRepo.ListControllers(ctx, server.WithLiveness(time.Duration(ws.livenessTimeToStale.Load())))
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting current controllers"))
		return nil, status.Errorf(codes.Internal, "Error getting current controllers: %v", err)
	}

	responseControllers := []*pbs.UpstreamServer{}
	for _, c := range controllers {
		thisController := &pbs.UpstreamServer{
			Address: c.Address,
			Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
		}
		responseControllers = append(responseControllers, thisController)
	}

	workerAuthRepo, err := ws.workerAuthRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting worker auth repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to lookup worker auth info: %v", err)
	}

	authorizedDownstreams := &pbs.AuthorizedDownstreamWorkerList{}
	if len(req.GetConnectedWorkerPublicIds()) > 0 {
		knownConnectedWorkers, err := serverRepo.VerifyKnownWorkers(ctx, req.GetConnectedWorkerPublicIds())
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error getting known connected worker ids"))
			return nil, status.Errorf(codes.Internal, "Error getting known connected worker ids: %v", err)
		}
		authorizedDownstreams.WorkerPublicIds = knownConnectedWorkers
	}

	if len(req.GetConnectedUnmappedWorkerKeyIdentifiers()) > 0 {
		authorizedKeyIds, err := workerAuthRepo.FilterToAuthorizedWorkerKeyIds(ctx, req.GetConnectedUnmappedWorkerKeyIdentifiers())
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error getting authorized unmapped worker key ids"))
			return nil, status.Errorf(codes.Internal, "Error getting authorized worker key ids: %v", err)
		}
		authorizedDownstreams.UnmappedWorkerKeyIdentifiers = authorizedKeyIds
	}

	ret := &pbs.StatusResponse{
		CalculatedUpstreams:         responseControllers,
		WorkerId:                    workerId,
		AuthorizedDownstreamWorkers: authorizedDownstreams,
	}

	stateReport := make([]*session.StateReport, 0, len(req.GetJobs()))
	var monitoredSessionIds []string

	for _, jobStatus := range req.GetJobs() {
		switch jobStatus.Job.GetType() {
		case pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION:
			si := jobStatus.GetJob().GetMonitorSessionInfo()
			if si == nil {
				return nil, status.Error(codes.Internal, "Error getting monitored session info at status time")
			}
			switch si.Status {
			case pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
				pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED:
				// No need to see about canceling anything
				continue
			}

			monitoredSessionIds = append(monitoredSessionIds, si.GetSessionId())
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

			sr := &session.StateReport{
				SessionId:   si.GetSessionId(),
				Connections: make([]*session.Connection, 0, len(si.GetConnections())),
			}
			for _, conn := range si.GetConnections() {
				switch conn.Status {
				case pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
					pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
					sr.Connections = append(sr.Connections, &session.Connection{
						PublicId:  conn.GetConnectionId(),
						BytesUp:   conn.GetBytesUp(),
						BytesDown: conn.GetBytesDown(),
					})
				}
			}
			stateReport = append(stateReport, sr)
		}
	}

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting sessions repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting connection repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}

	notActive, err := session.WorkerStatusReport(ctx, sessRepo, connectionRepo, workerId, stateReport)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Error comparing state of sessions for worker with public id %q: %v",
			workerId, err)
	}
	for _, na := range notActive {
		var connChanges []*pbs.Connection
		for _, conn := range na.Connections {
			connChanges = append(connChanges, &pbs.Connection{
				ConnectionId: conn.GetPublicId(),
				Status:       session.StatusClosed.ProtoVal(),
			})
		}
		processErr := pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNSPECIFIED
		if na.Unrecognized {
			processErr = pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNRECOGNIZED
		}
		ret.JobsRequests = append(ret.JobsRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_SESSION,
				JobInfo: &pbs.Job_SessionInfo{
					SessionInfo: &pbs.SessionJobInfo{
						SessionId:       na.SessionId,
						Status:          na.Status.ProtoVal(),
						Connections:     connChanges,
						ProcessingError: processErr,
					},
				},
			},
			RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
		})
	}

	nonActiveMonitoredSessions, err := sessRepo.CheckIfNotActive(ctx, monitoredSessionIds)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Error checking if monitored jobs are no longer active: %v", err)
	}
	for _, na := range nonActiveMonitoredSessions {
		processErr := pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNSPECIFIED
		if na.Unrecognized {
			processErr = pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNRECOGNIZED
		}
		ret.JobsRequests = append(ret.JobsRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
				JobInfo: &pbs.Job_MonitorSessionInfo{
					MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
						SessionId:       na.SessionId,
						Status:          na.Status.ProtoVal(),
						ProcessingError: processErr,
					},
				},
			},
			RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
		})
	}

	err = serverRepo.UpsertSessionInfo(ctx, workerId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error updating the latest status time for the server session info: %v", err)
	}

	return ret, nil
}

// ListHcpbWorkers looks up workers that are HCP Boundary-managed.
func (ws *workerServiceServer) ListHcpbWorkers(ctx context.Context, req *pbs.ListHcpbWorkersRequest) (*pbs.ListHcpbWorkersResponse, error) {
	const op = "workers.(workerServiceServer).ListHcpbWorkers"

	serversRepo, err := ws.serversRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting servers repo: %v", err)
	}

	// We use the livenessTimeToStale here instead of WorkerRPCGracePeriod
	// since WorkerRPCGracePeriod is more for deciding which workers should
	// be used for session proxying, but here we care about providing the BYOW
	// workers with a list of which upstreams to connect to as their upstreams.
	managed, err := serversRepo.ListHcpbManagedWorkers(ctx, time.Duration(ws.livenessTimeToStale.Load()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error looking up hcpb managed workers: %v", err)
	}

	resp := &pbs.ListHcpbWorkersResponse{}
	if len(managed) == 0 {
		return resp, nil
	}

	resp.Workers = make([]*pbs.WorkerInfo, 0, len(managed))
	for _, worker := range managed {
		resp.Workers = append(resp.Workers, &pbs.WorkerInfo{
			Id:      worker.PublicId,
			Address: worker.Address,
		})
	}

	return resp, nil
}

func (ws *workerServiceServer) RoutingInfo(ctx context.Context, req *pbs.RoutingInfoRequest) (*pbs.RoutingInfoResponse, error) {
	const op = "workers.(workerServiceServer).RoutingInfo"
	wStat := req.GetWorkerStatus()
	if wStat == nil {
		return nil, status.Error(codes.InvalidArgument, "worker status is required")
	}
	switch {
	case wStat.GetPublicId() == "" && wStat.GetKeyId() == "" && wStat.GetName() == "":
		return nil, status.Error(codes.InvalidArgument, "public id, key id and name are not set in the request; one is required")
	case wStat.GetAddress() == "":
		return nil, status.Error(codes.InvalidArgument, "address is not set but is required")
	case wStat.GetReleaseVersion() == "":
		return nil, status.Error(codes.InvalidArgument, "release version is not set but is required")
	case wStat.GetOperationalState() == "":
		return nil, status.Error(codes.InvalidArgument, "operational state is not set but is required")
	case wStat.GetLocalStorageState() == "":
		return nil, status.Error(codes.InvalidArgument, "local storage state is not set but is required")
	}
	// This Store call is currently only for testing purposes
	ws.updateTimes.Store(wStat.GetName(), time.Now())

	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting server repo: %v", err)
	}
	workerAuthRepo, err := ws.workerAuthRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting worker auth repo: %v", err)
	}

	// Convert API tags to storage tags
	workerTags := make([]*server.Tag, 0, len(wStat.GetTags()))
	for _, v := range wStat.GetTags() {
		workerTags = append(workerTags, &server.Tag{
			Key:   v.GetKey(),
			Value: v.GetValue(),
		})
	}

	wConf := server.NewWorker(
		scope.Global.String(),
		server.WithName(wStat.GetName()),
		server.WithDescription(wStat.GetDescription()),
		server.WithAddress(wStat.GetAddress()),
		server.WithWorkerTags(workerTags...),
		server.WithReleaseVersion(wStat.ReleaseVersion),
		server.WithOperationalState(wStat.OperationalState),
		server.WithLocalStorageState(wStat.LocalStorageState),
	)
	opts := []server.Option{server.WithUpdateTags(req.GetUpdateTags())}
	if wStat.GetPublicId() != "" {
		opts = append(opts, server.WithPublicId(wStat.GetPublicId()))
	}
	if wStat.GetKeyId() != "" {
		opts = append(opts, server.WithKeyId(wStat.GetKeyId()))
	}
	workerId, err := serverRepo.UpsertWorkerStatus(ctx, wConf, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}

	if sbcStates := wStat.GetStorageBucketCredentialStates(); sbcStates != nil {
		updateWorkerStorageBucketCredentialStatesFn(ctx, serverRepo, workerId, sbcStates)
	}

	controllers, err := serverRepo.ListControllers(ctx, server.WithLiveness(time.Duration(ws.livenessTimeToStale.Load())))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting current controllers: %v", err)
	}
	var upstreamAddresses []string
	for _, c := range controllers {
		upstreamAddresses = append(upstreamAddresses, c.Address)
	}

	authorizedDownstreams, err := server.VerifyKnownAndUnmappedWorkers(
		ctx,
		serverRepo,
		workerAuthRepo,
		req.GetConnectedWorkerPublicIds(),
		req.GetConnectedUnmappedWorkerKeyIdentifiers(),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting known and authorized workers: %v", err)
	}

	ret := &pbs.RoutingInfoResponse{
		WorkerId:                    workerId,
		CalculatedUpstreamAddresses: upstreamAddresses,
		AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{
			WorkerPublicIds:              authorizedDownstreams.WorkerPublicIds,
			UnmappedWorkerKeyIdentifiers: authorizedDownstreams.UnmappedWorkerKeyIds,
		},
	}
	return ret, nil
}

// Single-hop filter lookup. We have either an egress filter or worker filter to use, if any
// Used to verify that the worker serving this session to a client matches this filter
func egressFilterSelector(sessionInfo *session.Session) string {
	if sessionInfo.EgressWorkerFilter != "" {
		return sessionInfo.EgressWorkerFilter
	} else if sessionInfo.WorkerFilter != "" {
		return sessionInfo.WorkerFilter
	}
	return ""
}

// noProtocolContext doesn't provide any protocol context since tcp doesn't need any
func noProtocolContext(
	context.Context,
	*session.Repository,
	*server.Repository,
	common.WorkerAuthRepoStorageFactory,
	*pbs.AuthorizeConnectionRequest,
	[]string,
	string,
	intglobals.ControllerExtension,
) (*anypb.Any, error) {
	return nil, nil
}

func lookupSessionWorkerFilter(ctx context.Context, sessionInfo *session.Session, authzSummary *session.AuthzSummary, ws *workerServiceServer,
	req *pbs.LookupSessionRequest,
) error {
	const op = "workers.lookupSessionEgressWorkerFilter"

	serversRepo, err := ws.serversRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting server repo"))
		return status.Errorf(codes.Internal, "Error acquiring server repo when looking up session: %v", err)
	}
	w, err := serversRepo.LookupWorker(ctx, req.GetWorkerId())
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error looking up worker", "worker_id", req.WorkerId))
		return status.Errorf(codes.Internal, "Error looking up worker: %v", err)
	}
	if w == nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error looking up worker", "worker_id", req.WorkerId))
		return status.Errorf(codes.Internal, "Worker not found")
	}

	filter := workerFilterSelectionFn(sessionInfo)
	if filter == "" {
		// Verify that this ingress worker can build a route to the endpoint safely
		// While the AuthorizeSession may have done a similar check, this makes sure
		// we can select a worker for egress that wouldn't potentially grant access
		// to a private ip address in the network of the boundary deployment in the
		// case of hcp.
		if _, err := connectionRouteFn(ctx, w, sessionInfo, serversRepo, ws.downstreams); err != nil {
			return status.Errorf(codes.Internal, "error calculating route to endpoint: %v", err)
		}
		return nil
	}

	// Build the map for filtering.
	tagMap := w.CanonicalTags()

	// Create the evaluator
	eval, err := bexpr.CreateEvaluator(filter)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error creating worker filter evaluator", "worker_id", req.WorkerId))
		return status.Errorf(codes.Internal, "Error creating worker filter evaluator: %v", err)
	}
	filterInput := map[string]interface{}{
		"name": w.GetName(),
		"tags": tagMap,
	}
	ok, err := eval.Evaluate(filterInput)
	if err != nil {
		return status.Errorf(codes.Internal, "Worker filter expression evaluation resulted in error: %s", err)
	}
	if !ok {
		return handlers.ApiErrorWithCodeAndMessage(codes.FailedPrecondition, "Worker filter expression precludes this worker from serving this session")
	}

	// Verify that this ingress worker can build a route to the endpoint safely
	// While the AuthorizeSession may have done a similar check, this makes sure
	// we can select a worker for egress that wouldn't potentially grant access
	// to a private ip address in the network of the boundary deployment in the
	// case of hcp.
	if _, err = connectionRouteFn(ctx, w, sessionInfo, serversRepo, ws.downstreams); err != nil {
		return status.Errorf(codes.Internal, "error calculating route to endpoint: %v", err)
	}

	return nil
}

func (ws *workerServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	const op = "workers.(workerServiceServer).LookupSession"

	if req.WorkerId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Did not receive worker id when looking up session")
	}

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

	err = lookupSessionWorkerFilter(ctx, sessionInfo, authzSummary, ws, req)
	if err != nil {
		return nil, err
	}

	creds, err := sessRepo.ListSessionCredentials(ctx, sessionInfo.ProjectId, sessionInfo.PublicId)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Error retrieving session credentials: %s", err)
	}
	var workerCreds []*pbs.Credential
	for _, c := range creds {
		m := &pbs.Credential{}
		err = proto.Unmarshal(c, m)
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"Error unmarshaling credentials: %s", err)
		}
		workerCreds = append(workerCreds, m)
	}

	resp := &pbs.LookupSessionResponse{
		Authorization: &targets.SessionAuthorizationData{
			SessionId:   sessionInfo.GetPublicId(),
			Certificate: sessionInfo.Certificate,
			PrivateKey:  sessionInfo.CertificatePrivateKey,
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
	if ses == nil {
		return nil, status.Error(codes.PermissionDenied, "Unknown session ID.")
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

	serversRepo, err := ws.serversRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting server repo: %v", err)
	}
	w, err := serversRepo.LookupWorker(ctx, req.GetWorkerId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error looking up worker: %v", err)
	}
	if w == nil {
		return nil, status.Errorf(codes.NotFound, "worker not found with name %q", req.GetWorkerId())
	}

	connectionInfo, err := connectionRepo.AuthorizeConnection(ctx, req.GetSessionId(), w.GetPublicId())
	if err != nil {
		return nil, err
	}
	if connectionInfo == nil {
		return nil, status.Error(codes.Internal, "Invalid authorize connection response.")
	}

	sessInfo, authzSummary, err := sessionRepo.LookupSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if sessInfo == nil {
		return nil, status.Errorf(codes.Internal, "Invalid session info in lookup session response")
	}

	route, err := connectionRouteFn(ctx, w, sessInfo, serversRepo, ws.downstreams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting route to egress worker: %v", err)
	}

	ret := &pbs.AuthorizeConnectionResponse{
		ConnectionId:    connectionInfo.GetPublicId(),
		Status:          session.ConnectionStatusFromString(connectionInfo.Status).ProtoVal(),
		ConnectionsLeft: authzSummary.ConnectionLimit,
		Route:           route,
	}
	if pc, err := getProtocolContext(
		ctx,
		sessionRepo,
		serversRepo,
		ws.workerAuthRepoFn,
		req,
		route,
		ret.ConnectionId,
		ws.controllerExt,
	); err != nil {
		return nil, err
	} else {
		ret.ProtocolContext = pc
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

	connectionInfo, err := connRepo.ConnectConnection(ctx, session.ConnectWith{
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
		Status: session.ConnectionStatusFromString(connectionInfo.Status).ProtoVal(),
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
		closeData = append(closeData, &pbs.CloseConnectionResponseData{
			ConnectionId: v.Connection.GetPublicId(),
			Status:       v.ConnectionState.ProtoVal(),
		})
	}

	ret := &pbs.CloseConnectionResponse{
		CloseResponseData: closeData,
	}

	return ret, nil
}

func updateWorkerStorageBucketCredentialStates(ctx context.Context, repo *server.Repository, workerId string, states map[string]*plugin.StorageBucketCredentialState) {
	const op = "handlers.updateWorkerStorageBucketCredentialStates"
	return
}
