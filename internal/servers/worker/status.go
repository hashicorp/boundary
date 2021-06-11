package worker

import (
	"context"
	"math/rand"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/resolver"
)

// In the future we could make this configurable
const (
	statusInterval = 2 * time.Second
	statusTimeout  = 5 * time.Second
)

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime time.Time
}

func (w *Worker) startStatusTicking(cancelCtx context.Context) {
	go func() {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		// This function exists to desynchronize calls to controllers from
		// workers so we aren't always getting status updates at the exact same
		// intervals, to ease the load on the DB.
		getRandomInterval := func() time.Duration {
			// 0 to 0.5 adjustment to the base
			f := r.Float64() / 2
			// Half a chance to be faster, not slower
			if r.Float32() > 0.5 {
				f = -1 * f
			}
			return statusInterval + time.Duration(f*float64(time.Second))
		}

		timer := time.NewTimer(0)
		for {
			select {
			case <-cancelCtx.Done():
				w.logger.Info("status ticking shutting down")
				return

			case <-timer.C:
				w.sendWorkerStatus(cancelCtx)
				timer.Reset(getRandomInterval())
			}
		}
	}()
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
	w.logger.Debug("waiting for next status report to controller")
	waitStatusStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, w.conf.StatusGracePeriodDuration)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			w.logger.Error("error waiting for next status report to controller", "err", err)
			break
		}

		if w.lastSuccessfulStatusTime().Sub(waitStatusStart) > 0 {
			break
		}

		time.Sleep(time.Second)
	}

	return ctx.Err()
}

func (w *Worker) sendWorkerStatus(cancelCtx context.Context) {
	// First send info as-is. We'll perform cleanup duties after we
	// get cancel/job change info back.
	var activeJobs []*pbs.JobStatus

	// Range over known sessions and collect info
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		var jobInfo pbs.SessionJobInfo
		sessionId := key.(string)
		si := value.(*sessionInfo)
		si.RLock()
		status := si.status
		connections := make([]*pbs.Connection, 0, len(si.connInfoMap))
		for k, v := range si.connInfoMap {
			connections = append(connections, &pbs.Connection{
				ConnectionId: k,
				Status:       v.status,
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
	var tags map[string]*servers.TagValues
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every status call.
	if w.updateTags.Load() {
		tags = w.tags.Load().(map[string]*servers.TagValues)
	}
	statusCtx, statusCancel := context.WithTimeout(cancelCtx, statusTimeout)
	defer statusCancel()
	result, err := client.Status(statusCtx, &pbs.StatusRequest{
		Jobs: activeJobs,
		Worker: &servers.Server{
			PrivateId:   w.conf.RawConfig.Worker.Name,
			Type:        resource.Worker.String(),
			Description: w.conf.RawConfig.Worker.Description,
			Address:     w.conf.RawConfig.Worker.PublicAddr,
			Tags:        tags,
		},
		UpdateTags: w.updateTags.Load(),
	})
	if err != nil {
		w.logger.Error("error making status request to controller", "error", err)
		// Check for last successful status. Ignore nil last status, this probably
		// means that we've never connected to a controller, and as such probably
		// don't have any sessions to worry about anyway.
		//
		// If a length of time has passed since we've been able to communicate, we
		// want to start terminating all sessions as a "break glass" kind of
		// scenario, as there will be no way we can really tell if these
		// connections should continue to exist.

		if isPastGrace, lastStatusTime, gracePeriod := w.isPastGrace(); isPastGrace {
			w.logger.Warn("status error grace period has expired, canceling all sessions on worker",
				"last_status_time", lastStatusTime.String(),
				"grace_period", gracePeriod,
			)

			// Run a "cleanup" for all sessions that will not be caught by
			// our standard cleanup routine.
			w.cleanupConnections(cancelCtx, true)
		}
	} else {
		w.logger.Trace("successfully sent status to controller")
		w.updateTags.Store(false)
		addrs := make([]resolver.Address, 0, len(result.Controllers))
		strAddrs := make([]string, 0, len(result.Controllers))
		for _, v := range result.Controllers {
			addrs = append(addrs, resolver.Address{Addr: v.Address})
			strAddrs = append(strAddrs, v.Address)
		}
		w.logger.Trace("found controllers", "addresses", strAddrs)
		switch len(strAddrs) {
		case 0:
			w.logger.Warn("got no controller addresses from controller; possibly prior to first status save, not persisting")
		default:
			w.Resolver().UpdateState(resolver.State{Addresses: addrs})
		}
		w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now()})

		for _, request := range result.GetJobsRequests() {
			w.logger.Trace("got job request from controller", "request", request)
			switch request.GetRequestType() {
			case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE:
				switch request.GetJob().GetType() {
				case pbs.JOBTYPE_JOBTYPE_SESSION:
					sessInfo := request.GetJob().GetSessionInfo()
					sessionId := sessInfo.GetSessionId()
					siRaw, ok := w.sessionInfoMap.Load(sessionId)
					if !ok {
						w.logger.Warn("session change requested but could not find local information for it", "session_id", sessionId)
						continue
					}
					si := siRaw.(*sessionInfo)
					si.Lock()
					si.status = sessInfo.GetStatus()
					// Update connection state if there are any connections in
					// the request.
					for _, conn := range sessInfo.GetConnections() {
						connId := conn.GetConnectionId()
						connInfo, ok := si.connInfoMap[conn.GetConnectionId()]
						if !ok {
							w.logger.Warn("connection change requested but could not find local information for it", "connection_id", connId)
							continue
						}

						connInfo.status = conn.GetStatus()
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

// cleanupConnections walks all sessions and shuts down connections.
// Additionally, sessions without connections are cleaned up from the
// local worker's state.
//
// Use ignoreSessionState to ignore the state checks, this closes all
// connections, regardless of whether or not the session is still
// active.
func (w *Worker) cleanupConnections(cancelCtx context.Context, ignoreSessionState bool) {
	closeInfo := make(map[string]string)
	cleanSessionIds := make([]string, 0)
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		si := value.(*sessionInfo)
		si.Lock()
		defer si.Unlock()
		switch {
		case ignoreSessionState,
			si.status == pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			si.status == pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
			time.Until(si.lookupSessionResponse.Expiration.AsTime()) < 0:
			// Cancel connections without regard to individual connection
			// state.
			closedIds := w.cancelConnections(si.connInfoMap, true)
			for _, connId := range closedIds {
				closeInfo[connId] = si.id
				w.logClose(si.id, connId)
			}

			// closeTime is marked by closeConnections iff the
			// status is returned for that connection as closed. If
			// the session is no longer valid and all connections
			// are marked closed, clean up the session.
			if len(closedIds) == 0 {
				cleanSessionIds = append(cleanSessionIds, si.id)
			}

		default:
			// Cancel connections *with* regard to individual connection
			// state (ie: only ones that the controller has requested be
			// terminated).
			closedIds := w.cancelConnections(si.connInfoMap, false)
			for _, connId := range closedIds {
				closeInfo[connId] = si.id
				w.logClose(si.id, connId)
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
		w.closeConnections(cancelCtx, closeInfo)
	}

	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	for _, v := range cleanSessionIds {
		w.sessionInfoMap.Delete(v)
	}
}

// cancelConnections is run by cleanupConnections to iterate over a
// session's connInfoMap and close connections based on the
// connection's state (or regardless if ignoreConnectionState is
// set).
//
// The returned map and slice are the maps of connection -> session,
// and sessions to completely remove from local state, respectively.
func (w *Worker) cancelConnections(connInfoMap map[string]*connInfo, ignoreConnectionState bool) []string {
	var closedIds []string
	for k, v := range connInfoMap {
		if v.closeTime.IsZero() {
			if !ignoreConnectionState && v.status != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				continue
			}

			v.connCancel()
			closedIds = append(closedIds, k)
		}
	}

	return closedIds
}

func (w *Worker) logClose(sessionId, connId string) {
	w.logger.Info("terminated connection due to cancellation or expiration", "session_id", sessionId, "connection_id", connId)
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
