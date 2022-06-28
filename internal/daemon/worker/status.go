package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/server"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/resolver"
)

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime              time.Time
	LastCalculatedUpstreams []string
}

func (w *Worker) startStatusTicking(cancelCtx context.Context, sessionCache *session.Cache) {
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
			w.sendWorkerStatus(cancelCtx, sessionCache)
			timer.Reset(getRandomInterval())
		}
	}
}

// LastStatusSuccess reports the last time we sent a successful
// status request.
func (w *Worker) LastStatusSuccess() *LastStatusInformation {
	return w.lastStatusSuccess.Load().(*LastStatusInformation)
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
	ctx, cancel := context.WithTimeout(w.baseContext, w.conf.StatusGracePeriodDuration)
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

		if w.lastSuccessfulStatusTime().Sub(waitStatusStart) > 0 {
			break
		}
	}

	event.WriteSysEvent(ctx, op, "next worker status update sent successfully")
	return nil
}

func (w *Worker) sendWorkerStatus(cancelCtx context.Context, sessionCache *session.Cache) {
	const op = "worker.(Worker).sendWorkerStatus"

	// If we've never managed to successfully authenticate then we won't have
	// any session information anyways and this will produce a ton of noise in
	// observability, so suppress it
	if !w.everAuthenticated.Load() {
		event.WriteSysEvent(cancelCtx, op, "worker is not authenticated to an upstream, not sending status")
		return
	}

	// First send info as-is. We'll perform cleanup duties after we
	// get cancel/job change info back.
	var activeJobs []*pbs.JobStatus

	// Range over known sessions and collect info
	sessionCache.ForEachSession(func(s *session.Session) bool {
		var jobInfo pbs.SessionJobInfo
		status := s.GetStatus()
		sessionId := s.GetId()
		connections := make([]*pbs.Connection, 0, len(s.GetConnections()))
		for k, v := range s.GetConnections() {
			connections = append(connections, &pbs.Connection{
				ConnectionId: k,
				Status:       v.Status,
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
	client := w.controllerStatusConn.Load().(pbs.ServerCoordinationServiceClient)
	var tags []*server.TagPair
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every status call.
	if w.updateTags.Load() {
		tags = w.tags.Load().([]*server.TagPair)
	}
	statusCtx, statusCancel := context.WithTimeout(cancelCtx, common.StatusTimeout)
	defer statusCancel()

	keyId := w.WorkerAuthCurrentKeyId.Load()

	if w.conf.RawConfig.Worker.Name == "" && keyId == "" {
		event.WriteError(statusCtx, op, errors.New("worker name and keyId are both empty; one is needed to identify a worker"),
			event.WithInfoMsg("error making status request to controller"))
	}

	result, err := client.Status(statusCtx, &pbs.StatusRequest{
		Jobs: activeJobs,
		WorkerStatus: &server.ServerWorkerStatus{
			Name:        w.conf.RawConfig.Worker.Name,
			Description: w.conf.RawConfig.Worker.Description,
			Address:     w.conf.RawConfig.Worker.PublicAddr,
			Tags:        tags,
			KeyId:       keyId,
		},
		UpdateTags: w.updateTags.Load(),
	})
	if err != nil {
		event.WriteError(statusCtx, op, err, event.WithInfoMsg("error making status request to controller"))
		// Check for last successful status. Ignore nil last status, this probably
		// means that we've never connected to a controller, and as such probably
		// don't have any sessions to worry about anyway.
		//
		// If a length of time has passed since we've been able to communicate, we
		// want to start terminating all connections as a "break glass" kind of
		// scenario, as there will be no way we can really tell if these
		// connections should continue to exist.

		if isPastGrace, lastStatusTime, gracePeriod := w.isPastGrace(); isPastGrace {
			event.WriteError(statusCtx, op,
				errors.New("status error grace period has expired, canceling all sessions on worker"),
				event.WithInfo("last_status_time", lastStatusTime.String(), "grace_period", gracePeriod),
			)

			// Cancel connections if grace period has expired. These Connections will be closed in the
			// database on the next successful status report, or via the Controller’s dead Worker cleanup connections job.
			sessionCache.ForEachSession(func(s *session.Session) bool {
				for _, connId := range s.CancelAllConnections() {
					event.WriteSysEvent(cancelCtx, op, "terminated connection due to status grace period expiration", "session_id", s.GetId(), "connection_id", connId)
				}
				return true
			})

			// Exit out of status function; our work here is done and we don't need to create closeConnection requests
			return
		}
	} else {
		w.updateTags.Store(false)
		// This may be nil if we are in a multiple hop scenario
		var addrs []resolver.Address
		var newUpstreams []string
		if len(result.CalculatedUpstreams) > 0 {
			addrs = make([]resolver.Address, 0, len(result.CalculatedUpstreams))
			for _, v := range result.CalculatedUpstreams {
				addrs = append(addrs, resolver.Address{Addr: v.Address})
				newUpstreams = append(newUpstreams, v.Address)
			}
			lastStatus := w.lastStatusSuccess.Load().(*LastStatusInformation)
			// Compare upstreams; update resolver if there is a difference, and emit an event with old and new addresses
			if lastStatus != nil && !strutil.EquivalentSlices(lastStatus.LastCalculatedUpstreams, newUpstreams) {
				upstreamsMessage := fmt.Sprintf("Upstreams has changed; old upstreams were: %s, new upstreams are: %s", lastStatus.LastCalculatedUpstreams, newUpstreams)
				event.WriteSysEvent(cancelCtx, op, upstreamsMessage)
				w.Resolver().UpdateState(resolver.State{Addresses: addrs})
			} else if lastStatus == nil {
				w.Resolver().UpdateState(resolver.State{Addresses: addrs})
				event.WriteSysEvent(cancelCtx, op, fmt.Sprintf("Upstreams after first status set to: %s", newUpstreams))
			}
		}
		w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now(), LastCalculatedUpstreams: newUpstreams})

		for _, request := range result.GetJobsRequests() {
			switch request.GetRequestType() {
			case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE:
				switch request.GetJob().GetType() {
				case pbs.JOBTYPE_JOBTYPE_SESSION:
					sessInfo := request.GetJob().GetSessionInfo()
					sessionId := sessInfo.GetSessionId()
					si := sessionCache.Get(sessionId)
					if si == nil {
						event.WriteError(statusCtx, op, errors.New("session change requested but could not find local information for it"), event.WithInfo("session_id", sessionId))
						continue
					}
					si.ApplyStatus(sessInfo.GetStatus())

					// Update connection state if there are any connections in
					// the request.
					for _, conn := range sessInfo.GetConnections() {
						if err := si.ApplyConnectionStatus(conn.GetConnectionId(), conn.GetStatus()); err != nil {
							event.WriteError(statusCtx, op, err, event.WithInfo("connection_id", conn.GetConnectionId()))
						}
					}
				}
			}
		}
	}

	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(cancelCtx, false, sessionCache)
}

// cleanupConnections walks all sessions and shuts down all proxy connections.
// After the local connections are terminated, they are requested to be marked
// close on the controller.
// Additionally, sessions without connections are cleaned up from the
// local worker's state.
//
// Use ignoreSessionState to ignore the state checks, this closes all
// connections, regardless of whether or not the session is still active.
func (w *Worker) cleanupConnections(cancelCtx context.Context, ignoreSessionState bool, sessionCache *session.Cache) {
	const op = "worker.(Worker).cleanupConnections"
	closeInfo := make(map[string]string)
	cleanSessionIds := make([]string, 0)
	sessionCache.ForEachSession(func(s *session.Session) bool {
		switch {
		case ignoreSessionState,
			s.GetStatus() == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			s.GetStatus() == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
			time.Until(s.GetExpiration()) < 0:
			// Cancel connections without regard to individual connection
			// state.
			closedIds := s.CancelAllConnections()
			for _, connId := range closedIds {
				closeInfo[connId] = s.GetId()
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
			for _, connId := range s.CancelOpenConnections() {
				closeInfo[connId] = s.GetId()
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
		_ = sessionCache.RequestCloseConnections(cancelCtx, closeInfo)
	}
	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	sessionCache.DeleteSessionsLocally(cleanSessionIds)
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
	u := w.conf.StatusGracePeriodDuration
	v := time.Since(t)
	return v > u, t, u
}
