package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"google.golang.org/grpc/resolver"
)

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime              time.Time
	LastCalculatedUpstreams []resolver.Address
}

func (w *Worker) startStatusTicking(cancelCtx context.Context) {
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
			w.sendWorkerStatus(cancelCtx)
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

func (w *Worker) sendWorkerStatus(cancelCtx context.Context) {
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
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		var jobInfo pbs.SessionJobInfo
		sessionId := key.(string)
		si := value.(*session.Info)
		si.RLock()
		status := si.Status
		connections := make([]*pbs.Connection, 0, len(si.ConnInfoMap))
		for k, v := range si.ConnInfoMap {
			connections = append(connections, &pbs.Connection{
				ConnectionId: k,
				Status:       v.Status,
			})
		}
		si.RUnlock()
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
	var tags []*servers.TagPair
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every status call.
	if w.updateTags.Load() {
		tags = w.tags.Load().([]*servers.TagPair)
	}
	statusCtx, statusCancel := context.WithTimeout(cancelCtx, common.StatusTimeout)
	defer statusCancel()

	result, err := client.Status(statusCtx, &pbs.StatusRequest{
		Jobs: activeJobs,
		WorkerStatus: &servers.ServerWorkerStatus{
			Name:    w.conf.RawConfig.Worker.Name,
			Address: w.conf.RawConfig.Worker.PublicAddr,
			Tags:    tags,
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
			w.sessionInfoMap.Range(func(key, value interface{}) bool {
				si := value.(*session.Info)
				si.Lock()
				defer si.Unlock()

				closedIds := w.cancelConnections(si.ConnInfoMap, true)
				for _, connId := range closedIds {
					event.WriteSysEvent(cancelCtx, op, "terminated connection due to status grace period expiration", "session_id", si.Id, "connection_id", connId)
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
		if len(result.CalculatedUpstreams) > 0 {
			addrs = make([]resolver.Address, 0, len(result.CalculatedUpstreams))
			for _, v := range result.CalculatedUpstreams {
				addrs = append(addrs, resolver.Address{Addr: v.Address})
			}
			lastStatus := w.lastStatusSuccess.Load().(*LastStatusInformation)
			// Compare upstreams; update resolver if there is a difference, and emit an event with old and new addresses
			if lastStatus != nil && upstreamsHasChanged(lastStatus.LastCalculatedUpstreams, addrs) {
				var oldUpstreams []string
				for _, v := range lastStatus.LastCalculatedUpstreams {
					oldUpstreams = append(oldUpstreams, v.Addr)
				}
				var newUpstreams []string
				for _, v := range addrs {
					newUpstreams = append(newUpstreams, v.Addr)
				}
				upstreamsMessage := fmt.Sprintf("Upstreams has changed; old upstreams were: %s, new upstreams are: %s", oldUpstreams, newUpstreams)
				event.WriteSysEvent(context.TODO(), op, upstreamsMessage)
				w.Resolver().UpdateState(resolver.State{Addresses: addrs})
			}
		}
		w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now(), LastCalculatedUpstreams: addrs})

		for _, request := range result.GetJobsRequests() {
			switch request.GetRequestType() {
			case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE:
				switch request.GetJob().GetType() {
				case pbs.JOBTYPE_JOBTYPE_SESSION:
					sessInfo := request.GetJob().GetSessionInfo()
					sessionId := sessInfo.GetSessionId()
					siRaw, ok := w.sessionInfoMap.Load(sessionId)
					if !ok {
						event.WriteError(statusCtx, op, errors.New("session change requested but could not find local information for it"), event.WithInfo("session_id", sessionId))
						continue
					}
					si := siRaw.(*session.Info)
					si.Lock()
					si.Status = sessInfo.GetStatus()
					// Update connection state if there are any connections in
					// the request.
					for _, conn := range sessInfo.GetConnections() {
						connId := conn.GetConnectionId()
						connInfo, ok := si.ConnInfoMap[connId]
						if !ok {
							event.WriteError(statusCtx, op, errors.New("connection change requested but could not find local information for it"), event.WithInfo("connection_id", connId))
							continue
						}

						connInfo.Status = conn.GetStatus()
					}

					si.Unlock()
				}
			}
		}
	}

	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(cancelCtx, false)
}

func upstreamsHasChanged(oldUpstreams, newUpstreams []resolver.Address) bool {
	if len(oldUpstreams) != len(newUpstreams) {
		return true
	}

	// Sort both upstreams
	sort.Slice(oldUpstreams, func(i, j int) bool {
		return strings.Compare(oldUpstreams[i].Addr, oldUpstreams[j].Addr) < 0
	})
	sort.Slice(newUpstreams, func(i, j int) bool {
		return strings.Compare(newUpstreams[i].Addr, newUpstreams[j].Addr) < 0
	})

	// Compare and return true if change detected
	for i, _ := range oldUpstreams {
		if oldUpstreams[i].Addr != newUpstreams[i].Addr {
			return true
		}
	}
	return false
}

// cleanupConnections walks all sessions and shuts down connections.
// Additionally, sessions without connections are cleaned up from the
// local worker's state.
//
// Use ignoreSessionState to ignore the state checks, this closes all
// connections, regardless of whether or not the session is still
// active.
func (w *Worker) cleanupConnections(cancelCtx context.Context, ignoreSessionState bool) {
	const op = "worker.(Worker).cleanupConnections"
	closeInfo := make(map[string]string)
	cleanSessionIds := make([]string, 0)
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		si := value.(*session.Info)
		si.Lock()
		defer si.Unlock()
		switch {
		case ignoreSessionState,
			si.Status == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			si.Status == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
			time.Until(si.LookupSessionResponse.Expiration.AsTime()) < 0:
			// Cancel connections without regard to individual connection
			// state.
			closedIds := w.cancelConnections(si.ConnInfoMap, true)
			for _, connId := range closedIds {
				closeInfo[connId] = si.Id
				event.WriteSysEvent(cancelCtx, op, "terminated connection due to cancellation or expiration", "session_id", si.Id, "connection_id", connId)
			}

			// CloseTime is marked by CloseConnections iff the
			// status is returned for that connection as closed. If
			// the session is no longer valid and all connections
			// are marked closed, clean up the session.
			if len(closedIds) == 0 {
				cleanSessionIds = append(cleanSessionIds, si.Id)
			}

		default:
			// Cancel connections *with* regard to individual connection
			// state (ie: only ones that the controller has requested be
			// terminated).
			closedIds := w.cancelConnections(si.ConnInfoMap, false)
			for _, connId := range closedIds {
				closeInfo[connId] = si.Id
				event.WriteSysEvent(cancelCtx, op, "terminated connection due to cancellation or expiration", "session_id", si.Id, "connection_id", connId)
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
		sessClient, err := w.ControllerSessionConn()
		if err != nil {
			event.WriteError(cancelCtx, op, err, event.WithInfo("failed to create controller session client, connections won't be cleaned up"))
		} else {
			session.CloseConnections(cancelCtx, sessClient, w.sessionInfoMap, closeInfo)
		}
	}

	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	for _, v := range cleanSessionIds {
		w.sessionInfoMap.Delete(v)
	}
}

// cancelConnections is run by cleanupConnections to iterate over a
// session's ConnInfoMap and close connections based on the
// connection's state (or regardless if ignoreConnectionState is
// set).
//
// The returned map and slice are the maps of connection -> session,
// and sessions to completely remove from local state, respectively.
func (w *Worker) cancelConnections(connInfoMap map[string]*session.ConnInfo, ignoreConnectionState bool) []string {
	var closedIds []string
	for k, v := range connInfoMap {
		if v.CloseTime.IsZero() {
			if !ignoreConnectionState && v.Status != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				continue
			}

			v.ConnCancel()
			closedIds = append(closedIds, k)
		}
	}

	return closedIds
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
