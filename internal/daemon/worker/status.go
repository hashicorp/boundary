// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/connectivity"
)

var firstStatusCheckPostHooks []func(context.Context, *Worker) error

var downstreamWorkersFactory func(ctx context.Context, workerId string, ver string) (downstreamers, error)

var checkHCPBUpstreams func(w *Worker) bool

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime              time.Time
	LastCalculatedUpstreams []string
}

func (w *Worker) startStatusTicking(cancelCtx context.Context, sessionManager session.Manager, addrReceivers *[]addressReceiver, recorderManager recorderManager) {
	const op = "worker.(Worker).startStatusTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// This function exists to desynchronize calls to controllers from
	// workers, so we aren't always getting status updates at the exact same
	// intervals, to ease the load on the DB.
	getRandomInterval := func() time.Duration {
		// 0 to 0.5 adjustment to the base
		f := r.Float64() / 2
		// Half a chance to be faster, not slower
		if r.Float32() > 0.5 {
			f = -1 * f
		}
		return common.StatusInterval + time.Duration(f*float64(time.Second))
	}

	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "status ticking shutting down")
			return

		case <-timer.C:
			// If we've never managed to successfully authenticate then we won't have
			// any session information anyways and this will produce a ton of noise in
			// observability, so skip calling the function and retry in a short duration
			if w.everAuthenticated.Load() == authenticationStatusNeverAuthenticated {
				timer.Reset(10 * time.Millisecond)
				continue
			}

			w.sendWorkerStatus(cancelCtx, sessionManager, addrReceivers, recorderManager)
			timer.Reset(getRandomInterval())
		}
	}
}

// LastStatusSuccess reports the last time we sent a successful
// status request.
func (w *Worker) LastStatusSuccess() *LastStatusInformation {
	s, ok := w.lastStatusSuccess.Load().(*LastStatusInformation)
	if !ok {
		return nil
	}
	return s
}

// WaitForNextSuccessfulStatusUpdate waits for the next successful status. It's
// used by testing (and in the future, shutdown) in place of a more opaque and
// possibly unnecessarily long sleep for things like initial controller
// check-in, etc.
//
// The timeout is aligned with the worker's status grace period. A nil error
// means the status was sent successfully.
func (w *Worker) WaitForNextSuccessfulStatusUpdate() error {
	const op = "worker.(Worker).WaitForNextSuccessfulStatusUpdate"
	waitStatusStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, time.Duration(w.successfulStatusGracePeriod.Load()))
	defer cancel()
	event.WriteSysEvent(ctx, op, "waiting for next status report to controller")
	for {
		select {
		case <-time.After(time.Second):
			// pass

		case <-ctx.Done():
			event.WriteError(ctx, op, ctx.Err(), event.WithInfoMsg("error waiting for next status report to controller"))
			return ctx.Err()
		}

		if w.lastSuccessfulStatusTime().After(waitStatusStart) {
			break
		}
	}

	event.WriteSysEvent(ctx, op, "next worker status update sent successfully")
	return nil
}

func (w *Worker) sendWorkerStatus(cancelCtx context.Context, sessionManager session.Manager, addressReceivers *[]addressReceiver, recorderManager recorderManager) {
	const op = "worker.(Worker).sendWorkerStatus"
	w.statusLock.Lock()
	defer w.statusLock.Unlock()

	// Collect the different session ids that are being monitored by this worker
	var monitoredSessionIds []string

	if recorderManager != nil {
		recSessIds, err := recorderManager.SessionsManaged(cancelCtx)
		if err != nil {
			event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error getting session ids from recorderManager"))
		} else {
			monitoredSessionIds = append(monitoredSessionIds, recSessIds...)
		}
	}

	// First send info as-is. We'll perform cleanup duties after we
	// get cancel/job change info back.
	var activeJobs []*pbs.JobStatus

	for _, sid := range monitoredSessionIds {
		activeJobs = append(activeJobs, &pbs.JobStatus{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
				JobInfo: &pbs.Job_MonitorSessionInfo{
					MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
						SessionId: sid,
						Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					},
				},
			},
		})
	}

	// Range over known sessions and collect info
	sessionManager.ForEachLocalSession(func(s session.Session) bool {
		var jobInfo pbs.SessionJobInfo
		status := s.GetStatus()
		sessionId := s.GetId()
		localConnections := s.GetLocalConnections()
		connections := make([]*pbs.Connection, 0, len(localConnections))
		for k, v := range localConnections {
			connections = append(connections, &pbs.Connection{
				ConnectionId: k,
				Status:       v.Status,
				BytesUp:      v.BytesUp(),
				BytesDown:    v.BytesDown(),
			})
		}
		jobInfo.SessionId = sessionId
		activeJobs = append(activeJobs, &pbs.JobStatus{
			Job: &pbs.Job{
				Type: pbs.JOBTYPE_JOBTYPE_SESSION,
				JobInfo: &pbs.Job_SessionInfo{
					SessionInfo: &pbs.SessionJobInfo{
						SessionId:   sessionId,
						Status:      status,
						Connections: connections,
					},
				},
			},
		})
		return true
	})

	// Send status information
	client := pbs.NewServerCoordinationServiceClient(w.GrpcClientConn.Load())
	var tags []*pb.TagPair
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every status call.
	if w.updateTags.Load() {
		tags = w.tags.Load().([]*pb.TagPair)
	}
	statusCtx, statusCancel := context.WithTimeout(cancelCtx, time.Duration(w.statusCallTimeoutDuration.Load()))
	defer statusCancel()

	keyId := w.WorkerAuthCurrentKeyId.Load()
	switch {
	case w.conf.RawConfig.Worker.Name == "" && keyId == "":
		event.WriteError(cancelCtx, op, errors.New("worker name and keyId are both empty; at least one is needed to identify a worker"),
			event.WithInfoMsg("error making status request to controller"))
	}

	var storageBucketCredentialStates map[string]*plugin.StorageBucketCredentialState
	if w.RecordingStorage != nil {
		storageBucketCredentialStates = w.RecordingStorage.GetStorageBucketCredentialStates()
		// If the local storage state is unknown, and we have recording storage set, get the state from the recording storage
		// and set it on the worker. This is done once to ensure that the worker has the correct state for the first status
		// call.
		if w.localStorageState.Load() == server.UnknownLocalStorageState {
			w.localStorageState.Store(w.RecordingStorage.GetLocalStorageState(cancelCtx))
		}
	}
	versionInfo := version.Get()
	connectionState := w.downstreamConnManager.Connected()
	result, err := client.Status(statusCtx, &pbs.StatusRequest{
		Jobs: activeJobs,
		WorkerStatus: &pb.ServerWorkerStatus{
			Name:                          w.conf.RawConfig.Worker.Name,
			Description:                   w.conf.RawConfig.Worker.Description,
			Address:                       w.conf.RawConfig.Worker.PublicAddr,
			Tags:                          tags,
			KeyId:                         keyId,
			ReleaseVersion:                versionInfo.FullVersionNumber(false),
			OperationalState:              w.operationalState.Load().(server.OperationalState).String(),
			LocalStorageState:             w.localStorageState.Load().(server.LocalStorageState).String(),
			StorageBucketCredentialStates: storageBucketCredentialStates,
		},
		ConnectedWorkerKeyIdentifiers:         connectionState.AllKeyIds(),
		ConnectedUnmappedWorkerKeyIdentifiers: connectionState.UnmappedKeyIds(),
		ConnectedWorkerPublicIds:              connectionState.WorkerIds(),
		UpdateTags:                            w.updateTags.Load(),
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making status request to controller"))
		// Check for last successful status. Ignore nil last status, this probably
		// means that we've never connected to a controller, and as such probably
		// don't have any sessions to worry about anyway.
		//
		// If a length of time has passed since we've been able to communicate, we
		// want to start terminating all connections as a "break glass" kind of
		// scenario, as there will be no way we can really tell if these
		// connections should continue to exist.
		if isPastGrace, lastStatusTime, gracePeriod := w.isPastGrace(); isPastGrace {
			event.WriteError(cancelCtx, op,
				errors.New("status error grace period has expired, canceling all sessions on worker"),
				event.WithInfo("last_status_time", lastStatusTime.String(), "grace_period", gracePeriod),
			)

			// Cancel connections if grace period has expired. These Connections will be closed in the
			// database on the next successful status report, or via the Controller’s dead Worker cleanup connections job.
			sessionManager.ForEachLocalSession(func(s session.Session) bool {
				for _, connId := range s.CancelAllLocalConnections() {
					event.WriteSysEvent(cancelCtx, op, "terminated connection due to status grace period expiration", "session_id", s.GetId(), "connection_id", connId)
				}
				return true
			})

			// In the case that the control plane has gone down and come up with different IPs,
			// append initial upstreams/ cluster addr to the resolver to try
			if w.GrpcClientConn.Load().GetState() == connectivity.TransientFailure {
				lastStatus := w.lastStatusSuccess.Load().(*LastStatusInformation)
				if lastStatus != nil && lastStatus.LastCalculatedUpstreams != nil {
					addrs := lastStatus.LastCalculatedUpstreams

					if len(w.conf.RawConfig.Worker.InitialUpstreams) > 0 {
						addrs = append(addrs, w.conf.RawConfig.Worker.InitialUpstreams...)
					} else if HandleHcpbClusterId != nil && len(w.conf.RawConfig.HcpbClusterId) > 0 {
						clusterId, err := parseutil.ParsePath(w.conf.RawConfig.HcpbClusterId)
						if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
							event.WriteError(cancelCtx, op, err, event.WithInfoMsg("failed to parse HCP Boundary cluster ID"))
						} else {
							clusterAddress := HandleHcpbClusterId(clusterId)
							addrs = append(addrs, clusterAddress)
						}
					}

					addrs = strutil.RemoveDuplicates(addrs, false)
					if strutil.EquivalentSlices(lastStatus.LastCalculatedUpstreams, addrs) {
						// Nothing to update
						return
					}

					w.updateAddresses(cancelCtx, addrs, addressReceivers)
					lastStatus.LastCalculatedUpstreams = addrs
					w.lastStatusSuccess.Store(lastStatus)
				}
			}

			// Exit out of status function; our work here is done and we don't need to create closeConnection requests
			return
		}

		// Standard cleanup: Run through current jobs. Cancel connections
		// for any canceling session or any session that is expired.
		w.cleanupConnections(cancelCtx, false, sessionManager)
		return
	}

	w.updateTags.Store(false)

	if authorized := result.GetAuthorizedDownstreamWorkers(); authorized != nil {
		connectionState.DisconnectMissingWorkers(authorized.GetWorkerPublicIds())
		connectionState.DisconnectMissingUnmappedKeyIds(authorized.GetUnmappedWorkerKeyIdentifiers())
	} else if authorized := result.GetAuthorizedWorkers(); authorized != nil {
		connectionState.DisconnectAllMissingKeyIds(authorized.GetWorkerKeyIdentifiers())
	}
	var addrs []string
	// This may be empty if we are in a multiple hop scenario
	if len(result.CalculatedUpstreams) > 0 {
		addrs = make([]string, 0, len(result.CalculatedUpstreams))
		for _, v := range result.CalculatedUpstreams {
			addrs = append(addrs, v.Address)
		}
	} else if checkHCPBUpstreams != nil && checkHCPBUpstreams(w) {
		// This is a worker that is one hop away from managed workers, so attempt to get that list
		hcpbWorkersCtx, hcpbWorkersCancel := context.WithTimeout(cancelCtx, time.Duration(w.statusCallTimeoutDuration.Load()))
		defer hcpbWorkersCancel()
		workersResp, err := client.ListHcpbWorkers(hcpbWorkersCtx, &pbs.ListHcpbWorkersRequest{})
		if err != nil {
			event.WriteError(hcpbWorkersCtx, op, err, event.WithInfoMsg("error fetching managed worker information"))
		} else {
			addrs = make([]string, 0, len(workersResp.Workers))
			for _, v := range workersResp.Workers {
				addrs = append(addrs, v.Address)
			}
		}
	}

	w.updateAddresses(cancelCtx, addrs, addressReceivers)

	w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now(), LastCalculatedUpstreams: addrs})

	var nonActiveMonitoredSessionIds []string

	for _, request := range result.GetJobsRequests() {
		switch request.GetRequestType() {
		case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE:
			switch request.GetJob().GetType() {
			case pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION:
				si := request.GetJob().GetMonitorSessionInfo()
				if si != nil && si.Status != pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE {
					nonActiveMonitoredSessionIds = append(nonActiveMonitoredSessionIds, si.GetSessionId())
				}
			case pbs.JOBTYPE_JOBTYPE_SESSION:
				sessInfo := request.GetJob().GetSessionInfo()
				sessionId := sessInfo.GetSessionId()
				si := sessionManager.Get(sessionId)
				if si == nil {
					event.WriteError(cancelCtx, op, errors.New("session change requested but could not find local information for it"), event.WithInfo("session_id", sessionId))
					continue
				}
				si.ApplyLocalStatus(sessInfo.GetStatus())

				// Update connection state if there are any connections in
				// the request.
				for _, conn := range sessInfo.GetConnections() {
					if err := si.ApplyLocalConnectionStatus(conn.GetConnectionId(), conn.GetStatus()); err != nil {
						event.WriteError(cancelCtx, op, err, event.WithInfo("connection_id", conn.GetConnectionId()))
					}
				}
			}
		}
	}
	if recorderManager != nil {
		if err := recorderManager.ReauthorizeAllExcept(cancelCtx, nonActiveMonitoredSessionIds); err != nil {
			event.WriteError(cancelCtx, op, err)
		}
	}

	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(cancelCtx, false, sessionManager)

	// If we have post hooks for after the first status check, run them now
	if w.everAuthenticated.CompareAndSwap(authenticationStatusFirstAuthentication, authenticationStatusFirstStatusRpcSuccessful) {
		if downstreamWorkersFactory != nil {
			downstreamWorkers, err := downstreamWorkersFactory(cancelCtx, w.LastStatusSuccess().WorkerId, versionInfo.FullVersionNumber(false))
			if err != nil {
				event.WriteError(cancelCtx, op, err)
				w.conf.ServerSideShutdownCh <- struct{}{}
				return
			}
			w.downstreamWorkers.Store(&downstreamersContainer{downstreamers: downstreamWorkers})
		}
		for _, fn := range firstStatusCheckPostHooks {
			if err := fn(cancelCtx, w); err != nil {
				// If we can't verify status we can't be expected to behave
				// properly so error and trigger shutdown
				event.WriteError(cancelCtx, op, fmt.Errorf("error running first status check post hook: %w", err))
				// We don't use a non-blocking select here to ensure that it
				// happens; we should catch blocks in tests but we want to
				// ensure the signal is being listened to
				w.conf.ServerSideShutdownCh <- struct{}{}
				return
			}
		}
	}
}

// Update address receivers and dialing listeners with new addrs
func (w *Worker) updateAddresses(cancelCtx context.Context, addrs []string, addressReceivers *[]addressReceiver) {
	const op = "worker.(Worker).updateAddrs"

	if len(addrs) > 0 {
		lastStatus := w.lastStatusSuccess.Load().(*LastStatusInformation)
		// Compare upstreams; update resolver if there is a difference, and emit an event with old and new addresses
		if lastStatus != nil && !strutil.EquivalentSlices(lastStatus.LastCalculatedUpstreams, addrs) {
			upstreamsMessage := fmt.Sprintf("Upstreams has changed; old upstreams were: %s, new upstreams are: %s", lastStatus.LastCalculatedUpstreams, addrs)
			event.WriteSysEvent(cancelCtx, op, upstreamsMessage)
			for _, as := range *addressReceivers {
				as.SetAddresses(addrs)
			}
		} else if lastStatus == nil {
			for _, as := range *addressReceivers {
				as.SetAddresses(addrs)
			}
			event.WriteSysEvent(cancelCtx, op, fmt.Sprintf("Upstreams after first status set to: %s", addrs))
		}
	}

	// regardless of whether or not it's a new address, we need to set
	// them for secondary connections
	for _, as := range *addressReceivers {
		switch {
		case as.Type() == secondaryConnectionReceiverType:
			tmpAddrs := make([]string, len(addrs))
			copy(tmpAddrs, addrs)
			if len(tmpAddrs) == 0 {
				tmpAddrs = append(tmpAddrs, w.conf.RawConfig.Worker.InitialUpstreams...)
			}
			as.SetAddresses(tmpAddrs)
		}
	}
}

// cleanupConnections walks all sessions and shuts down all proxy connections.
// After the local connections are terminated, they are requested to be marked
// close on the controller.
// Additionally, sessions without connections are cleaned up from the
// local worker's state.
//
// Use ignoreSessionState to ignore the state checks, this closes all
// connections, regardless of whether or not the session is still active.
func (w *Worker) cleanupConnections(cancelCtx context.Context, ignoreSessionState bool, sessionManager session.Manager) {
	const op = "worker.(Worker).cleanupConnections"
	closeInfo := make(map[string]*session.ConnectionCloseData)
	cleanSessionIds := make([]string, 0)
	sessionManager.ForEachLocalSession(func(s session.Session) bool {
		switch {
		case ignoreSessionState,
			s.GetStatus() == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			s.GetStatus() == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
			time.Until(s.GetExpiration()) < 0:
			// Cancel connections without regard to individual connection
			// state.
			closedIds := s.CancelAllLocalConnections()
			localConns := s.GetLocalConnections()
			for _, connId := range closedIds {
				var bytesUp, bytesDown int64
				connInfo, ok := localConns[connId]
				if ok {
					bytesUp = connInfo.BytesUp()
					bytesDown = connInfo.BytesDown()
				}
				closeInfo[connId] = &session.ConnectionCloseData{
					SessionId: s.GetId(),
					BytesUp:   bytesUp,
					BytesDown: bytesDown,
				}
				event.WriteSysEvent(cancelCtx, op, "terminated connection due to cancellation or expiration", "session_id", s.GetId(), "connection_id", connId)
			}

			// If the session is no longer valid and all connections
			// are marked closed, clean up the session.
			if len(closedIds) == 0 {
				cleanSessionIds = append(cleanSessionIds, s.GetId())
			}

		default:
			// Cancel connections *with* regard to individual connection
			// state (ie: only ones that the controller has requested be
			// terminated).
			for _, connId := range s.CancelOpenLocalConnections() {
				closeInfo[connId] = &session.ConnectionCloseData{SessionId: s.GetId()}
				event.WriteSysEvent(cancelCtx, op, "terminated connection due to cancellation or expiration", "session_id", s.GetId(), "connection_id", connId)
			}
		}

		return true
	})

	// Note that we won't clean these from the info map until the
	// next time we run this function
	if len(closeInfo) > 0 {
		// Call out to a helper to send the connection close requests to the
		// controller, and set the close time. This functionality is shared with
		// post-close functionality in the proxy handler.
		_ = sessionManager.RequestCloseConnections(cancelCtx, closeInfo)
	}
	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	sessionManager.DeleteLocalSession(cleanSessionIds)
}

func (w *Worker) lastSuccessfulStatusTime() time.Time {
	lastStatus := w.LastStatusSuccess()
	if lastStatus == nil {
		return w.workerStartTime
	}

	return lastStatus.StatusTime
}

func (w *Worker) isPastGrace() (bool, time.Time, time.Duration) {
	t := w.lastSuccessfulStatusTime()
	u := time.Duration(w.successfulStatusGracePeriod.Load())
	v := time.Since(t)
	return v > u, t, u
}
