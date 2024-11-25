// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
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
	"github.com/hashicorp/boundary/version"
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
	downstreams         common.Downstreamers
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
func singleHopConnectionRoute(_ context.Context, w *server.Worker, _ *session.Session, _ *session.AuthzSummary, _ *server.Repository, _ common.Downstreamers) ([]string, error) {
	return []string{w.GetPublicId()}, nil
}

func NewWorkerServiceServer(
	serversRepoFn common.ServersRepoFactory,
	workerAuthRepoFn common.WorkerAuthRepoStorageFactory,
	sessionRepoFn session.RepositoryFactory,
	connectionRepoFn common.ConnectionRepoFactory,
	downstreams common.Downstreamers,
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

func calculateJobChanges(
	ctx context.Context,
	jobs []*pbs.JobStatus,
	sessRepo *session.Repository,
	connectionRepo *session.ConnectionRepository,
	workerId string,
) ([]*pbs.JobChangeRequest, error) {
	const op = "workers.calculateJobChanges"
	stateReport := make([]*session.StateReport, 0, len(jobs))
	var monitoredSessionIds []string

	for _, jobStatus := range jobs {
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

	var jobRequests []*pbs.JobChangeRequest
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
		// Tell the worker which managed sessions should be canceled
		jobRequests = append(jobRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_SESSION,
				JobInfo: &pbs.Job_SessionInfo{
					SessionInfo: &pbs.SessionJobInfo{
						SessionId: na.SessionId,
						// The status is either canceling or terminated at this point
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
		// Tell the worker which monitored sessions should be canceled
		jobRequests = append(jobRequests, &pbs.JobChangeRequest{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
				JobInfo: &pbs.Job_MonitorSessionInfo{
					MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
						SessionId: na.SessionId,
						// The status is either canceling or terminated at this point
						Status:          na.Status.ProtoVal(),
						ProcessingError: processErr,
					},
				},
			},
			RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
		})
	}

	return jobRequests, nil
}

func calculateUpstreams(
	ctx context.Context,
	serverRepo *server.Repository,
	livenessTimeToStale time.Duration,
) ([]*pbs.UpstreamServer, error) {
	const op = "workers.calculateUpstreams"

	controllers, err := serverRepo.ListControllers(ctx, server.WithLiveness(livenessTimeToStale))
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting current controllers"))
		return nil, status.Errorf(codes.Internal, "Error getting current controllers: %v", err)
	}

	var calculatedUpstreams []*pbs.UpstreamServer
	for _, c := range controllers {
		thisController := &pbs.UpstreamServer{
			Address: c.Address,
			Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
		}
		calculatedUpstreams = append(calculatedUpstreams, thisController)
	}

	return calculatedUpstreams, nil
}

func calculateDownstreams(
	ctx context.Context,
	serverRepo *server.Repository,
	workerAuthRepo *server.WorkerAuthRepositoryStorage,
	connectedWorkerPublicIds []string,
	connectedUnmappedWorkerKeyIdentifiers []string,
) (*pbs.AuthorizedDownstreamWorkerList, error) {
	const op = "workers.calculateDownstreams"

	authorizedDownstreamWorkers := &pbs.AuthorizedDownstreamWorkerList{}
	if len(connectedWorkerPublicIds) > 0 {
		knownConnectedWorkers, err := serverRepo.ListWorkers(ctx, []string{scope.Global.String()}, server.WithWorkerPool(connectedWorkerPublicIds), server.WithLiveness(-1))
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error getting known connected worker ids"))
			return nil, status.Errorf(codes.Internal, "Error getting known connected worker ids: %v", err)
		}
		authorizedDownstreamWorkers.WorkerPublicIds = server.WorkerList(knownConnectedWorkers).PublicIds()
	}

	if len(connectedUnmappedWorkerKeyIdentifiers) > 0 {
		authorizedKeyIds, err := workerAuthRepo.FilterToAuthorizedWorkerKeyIds(ctx, connectedUnmappedWorkerKeyIdentifiers)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error getting authorized unmapped worker key ids"))
			return nil, status.Errorf(codes.Internal, "Error getting authorized worker key ids: %v", err)
		}
		authorizedDownstreamWorkers.UnmappedWorkerKeyIdentifiers = authorizedKeyIds
	}

	return authorizedDownstreamWorkers, nil
}

func updateBytesUpBytesDown(
	ctx context.Context,
	connectionRepo *session.ConnectionRepository,
	sessions []*pbs.SessionStatistics,
) error {
	const op = "workers.UpdateBytesUpBytesDown"
	var reportedConnections []*session.Connection
	for _, si := range sessions {
		if si == nil {
			return status.Error(codes.Internal, "Error getting session info at status time")
		}

		for _, conn := range si.GetConnections() {
			reportedConnections = append(reportedConnections, &session.Connection{
				PublicId:  conn.GetConnectionId(),
				BytesUp:   conn.GetBytesUp(),
				BytesDown: conn.GetBytesDown(),
			})
		}
	}
	err := connectionRepo.UpdateBytesUpBytesDown(ctx, reportedConnections...)
	if err != nil {
		return errors.New(ctx, errors.Internal, op, fmt.Sprintf("failed to update bytes up and down for worker reported connections: %v", err))
	}
	connectionRepo.CloseOp
	return nil
}

func workerTooOld(controllerVer, workerVer *version.Info) bool {
	cSeg := controllerVer.Semver().Segments()
	cMajor := cSeg[0]
	cMinor := cSeg[1]
	wSeg := workerVer.Semver().Segments()
	wMajor := wSeg[0]
	wMinor := wSeg[1]

	// If we're older than 0.21, the worker version doesn't matter
	if cMajor == 0 && cMinor < 21 {
		return false
	}
	// If the worker version is greater than or equal to 0.19, we're ok
	if wMajor == 0 && wMinor >= 19 {
		return false
	}
	// Controller is >= 0.21 and worker is < 0.19, worker is too old
	return true
}

func (ws *workerServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	const op = "workers.(workerServiceServer).Status"

	workerVer := version.FromVersionString(req.GetReleaseVersion())
	if workerVer == nil {
		// Older workers will set the release version in the deprecated worker status
		workerVer = version.FromVersionString(req.GetWorkerStatus().GetReleaseVersion())
	}
	switch {
	case workerVer == nil:
		return nil, status.Error(codes.InvalidArgument, "ReleaseVersion is not set but is required.")
	case version.Get().Semver().LessThan(workerVer.Semver()):
		return nil, status.Errorf(codes.InvalidArgument, "Worker version %s is greater than the controller version", workerVer.FullVersionNumber(false))
	case workerTooOld(version.Get(), workerVer):
		return nil, status.Errorf(codes.FailedPrecondition, "Worker version %s is unsupported by the controller version, please upgrade", workerVer.FullVersionNumber(false))
	}
	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting server repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to store worker status: %v", err)
	}

	if version.SupportsFeature(workerVer.Semver(), version.MultipleWorkerStatusRpcs) {
		// If the worker uses multiple worker status RPCs, we just need to upsert the
		// update time in the DB and potentially generate a worker ID

		wConf := server.NewWorker(
			scope.Global.String(),
			server.WithReleaseVersion(workerVer.VersionNumber()),
		)
		var opts []server.Option
		if req.GetWorkerId() != "" {
			opts = append(opts, server.WithPublicId(req.GetWorkerId()))
		}
		if req.GetKeyId() != "" {
			opts = append(opts, server.WithKeyId(req.GetKeyId()))
		}
		wrk, err := serverRepo.UpsertWorkerStatus(ctx, wConf, opts...)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error storing worker status"))
			return nil, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
		}

		return &pbs.StatusResponse{
			WorkerId: wrk.GetPublicId(),
		}, nil
	}

	// This is an older worker that only supports a single status RPC, so we need to do the rest of the work
	// TODO: Remove the code below this line after the 0.21.0 release
	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting sessions repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting connection repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query connection status: %v", err)
	}
	workerAuthRepo, err := ws.workerAuthRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting worker auth repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to lookup worker auth info: %v", err)
	}

	wStat := req.GetWorkerStatus()
	if wStat == nil {
		return nil, status.Error(codes.InvalidArgument, "Worker sent nil status.")
	}
	switch {
	case wStat.GetName() == "" && wStat.GetKeyId() == "":
		return nil, status.Error(codes.InvalidArgument, "Name and keyId are not set in the request; one is required.")
	case wStat.GetAddress() == "":
		return nil, status.Error(codes.InvalidArgument, "Address is not set but is required.")
	case wStat.GetReleaseVersion() == "" || workerVer == nil:
		return nil, status.Error(codes.InvalidArgument, "ReleaseVersion is not set but is required.")
	case version.Get().Semver().LessThan(workerVer.Semver()):
		return nil, status.Errorf(codes.InvalidArgument, "Worker version %s is greater than the controller version", wStat.ReleaseVersion)
	case wStat.GetOperationalState() == "":
		return nil, status.Error(codes.InvalidArgument, "OperationalState is not set but is required.")
	case wStat.GetLocalStorageState() == "":
		return nil, status.Error(codes.InvalidArgument, "LocalStorageState is not set but is required.")
	}
	// This Store call is currently only for testing purposes
	ws.updateTimes.Store(wStat.GetName(), time.Now())

	// Convert API tags to storage tags
	wTags := wStat.GetTags()
	workerTags := make([]*server.Tag, 0, len(wTags))
	for _, v := range wTags {
		workerTags = append(workerTags, &server.Tag{
			Key:   v.GetKey(),
			Value: v.GetValue(),
		})
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
	wrk, err := serverRepo.UpsertWorkerStatus(ctx, wConf, opts...)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error storing worker status"))
		return nil, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}

	ret := &pbs.StatusResponse{
		WorkerId: wrk.GetPublicId(),
	}
	ret.JobsRequests, err = calculateJobChanges(ctx, req.GetJobs(), sessRepo, connectionRepo, wrk.GetPublicId())
	if err != nil {
		return nil, err
	}

	if sbcStates := wStat.GetStorageBucketCredentialStates(); sbcStates != nil && wrk.GetPublicId() != "" {
		updateWorkerStorageBucketCredentialStatesFn(ctx, serverRepo, wrk.GetPublicId(), sbcStates)
	}

	var sessions []*pbs.SessionJobInfo
	for _, job := range req.GetJobs() {
		if job.GetJob().GetType() == pbs.JOBTYPE_JOBTYPE_SESSION && job.GetJob().GetSessionInfo() != nil {
			sessions = append(sessions, job.Job.GetSessionInfo())
		}
	}

	// Convert incoming session stats to the new format
	var sessionStats []*pbs.SessionStatistics
	for _, si := range sessions {
		var sessionStat pbs.SessionStatistics
		switch si.Status {
		case pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED:
			// No need to see about canceling anything
			continue
		}

		for _, conn := range si.GetConnections() {
			switch conn.Status {
			case pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
				pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
				sessionStat.Connections = append(sessionStat.Connections, &pbs.ConnectionStatistics{
					ConnectionId: conn.GetConnectionId(),
					BytesUp:      conn.GetBytesUp(),
					BytesDown:    conn.GetBytesDown(),
				})
			}
		}
		sessionStats = append(sessionStats, &sessionStat)
	}

	if err := updateBytesUpBytesDown(ctx, connectionRepo, sessionStats); err != nil {
		return nil, err
	}

	ret.CalculatedUpstreams, err = calculateUpstreams(ctx, serverRepo, time.Duration(ws.livenessTimeToStale.Load()))
	if err != nil {
		return nil, err
	}

	ret.AuthorizedDownstreamWorkers, err = calculateDownstreams(
		ctx,
		serverRepo,
		workerAuthRepo,
		req.GetConnectedWorkerPublicIds(),
		req.GetConnectedUnmappedWorkerKeyIdentifiers(),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// ListHcpbWorkers looks up workers that are HCP Boundary-managed, currently by
// seeing if they are KMS and have a known tag
func (ws *workerServiceServer) ListHcpbWorkers(ctx context.Context, req *pbs.ListHcpbWorkersRequest) (*pbs.ListHcpbWorkersResponse, error) {
	const op = "workers.(workerServiceServer).ListHcpbWorkers"

	serversRepo, err := ws.serversRepoFn()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error getting servers repo: %v", err)
	}
	workers, err := serversRepo.ListWorkers(ctx, []string{scope.Global.String()},
		// We use the livenessTimeToStale here instead of WorkerStatusGracePeriod
		// since WorkerStatusGracePeriod is more for deciding which workers
		// should be used for session proxying, but here we care about providing
		// the BYOW workers with a list of which upstreams to connect to as their
		// upstreams.
		server.WithLiveness(time.Duration(ws.livenessTimeToStale.Load())))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error looking up workers: %v", err)
	}

	managed, _ := server.SeparateManagedWorkers(workers)
	resp := &pbs.ListHcpbWorkersResponse{}
	if len(managed) == 0 {
		return resp, nil
	}

	resp.Workers = make([]*pbs.WorkerInfo, 0, len(managed))
	for _, worker := range managed {
		resp.Workers = append(resp.Workers, &pbs.WorkerInfo{
			Id:      worker.GetPublicId(),
			Address: worker.GetAddress(),
		})
	}

	return resp, nil
}

func (ws *workerServiceServer) JobInfo(ctx context.Context, req *pbs.JobInfoRequest) (*pbs.JobInfoResponse, error) {
	const op = "workers.(workerServiceServer).JobInfo"

	switch {
	case req.GetWorkerId() == "":
		return nil, status.Error(codes.InvalidArgument, "Worker ID is required.")
	}

	sessRepo, err := ws.sessionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting sessions repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query session status: %v", err)
	}
	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting connection repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query connection status: %v", err)
	}

	ret := &pbs.JobInfoResponse{}

	ret.JobsRequests, err = calculateJobChanges(ctx, req.GetJobs(), sessRepo, connectionRepo, req.GetWorkerId())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (ws *workerServiceServer) RoutingInfo(ctx context.Context, req *pbs.RoutingInfoRequest) (*pbs.RoutingInfoResponse, error) {
	const op = "workers.(workerServiceServer).RoutingInfo"

	switch {
	case req.GetWorkerId() == "":
		return nil, status.Error(codes.InvalidArgument, "Worker ID is required.")
	}

	serverRepo, err := ws.serversRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting server repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to store worker status: %v", err)
	}
	workerAuthRepo, err := ws.workerAuthRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting worker auth repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to lookup worker auth info: %v", err)
	}

	// Convert API tags to storage tags
	wTags := req.GetTags()
	workerTags := make([]*server.Tag, 0, len(wTags))
	for _, v := range wTags {
		workerTags = append(workerTags, &server.Tag{
			Key:   v.GetKey(),
			Value: v.GetValue(),
		})
	}

	wConf := server.NewWorker(scope.Global.String(),
		server.WithPublicId(req.GetWorkerId()),
		server.WithWorkerTags(workerTags...),
		server.WithOperationalState(req.GetOperationalState()),
		server.WithLocalStorageState(req.GetLocalStorageState()))
	opts := []server.Option{server.WithUpdateTags(req.GetUpdateTags())}
	_, err = serverRepo.UpsertWorkerStatus(ctx, wConf, opts...)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error storing worker routing updates"))
		return nil, status.Errorf(codes.Internal, "Error storing worker status: %v", err)
	}

	if sbcStates := req.GetStorageBucketCredentialStates(); sbcStates != nil && req.GetWorkerId() != "" {
		updateWorkerStorageBucketCredentialStatesFn(ctx, serverRepo, req.GetWorkerId(), sbcStates)
	}

	ret := &pbs.RoutingInfoResponse{}
	ret.CalculatedUpstreams, err = calculateUpstreams(ctx, serverRepo, time.Duration(ws.livenessTimeToStale.Load()))
	if err != nil {
		return nil, err
	}

	ret.AuthorizedDownstreamWorkers, err = calculateDownstreams(
		ctx,
		serverRepo,
		workerAuthRepo,
		req.GetConnectedWorkerPublicIds(),
		req.GetConnectedUnmappedWorkerKeyIdentifiers(),
	)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (ws *workerServiceServer) Statistics(ctx context.Context, req *pbs.StatisticsRequest) (*pbs.StatisticsResponse, error) {
	const op = "workers.(workerServiceServer).Statistics"

	connectionRepo, err := ws.connectionRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting connection repo"))
		return nil, status.Errorf(codes.Internal, "Error acquiring repo to query connection status: %v", err)
	}
	if err := updateBytesUpBytesDown(ctx, connectionRepo, req.GetSessions()); err != nil {
		return nil, err
	}
	return &pbs.StatisticsResponse{}, nil
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
		if _, err := connectionRouteFn(ctx, w, sessionInfo, authzSummary, serversRepo, ws.downstreams); err != nil {
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
		return status.Errorf(codes.Internal, fmt.Sprintf("Worker filter expression evaluation resulted in error: %s", err))
	}
	if !ok {
		return handlers.ApiErrorWithCodeAndMessage(codes.FailedPrecondition, "Worker filter expression precludes this worker from serving this session")
	}

	// Verify that this ingress worker can build a route to the endpoint safely
	// While the AuthorizeSession may have done a similar check, this makes sure
	// we can select a worker for egress that wouldn't potentially grant access
	// to a private ip address in the network of the boundary deployment in the
	// case of hcp.
	if _, err = connectionRouteFn(ctx, w, sessionInfo, authzSummary, serversRepo, ws.downstreams); err != nil {
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
			fmt.Sprintf("Error retrieving session credentials: %s", err))
	}
	var workerCreds []*pbs.Credential
	for _, c := range creds {
		m := &pbs.Credential{}
		err = proto.Unmarshal(c, m)
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				fmt.Sprintf("Error unmarshaling credentials: %s", err))
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

	route, err := connectionRouteFn(ctx, w, sessInfo, authzSummary, serversRepo, ws.downstreams)
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
