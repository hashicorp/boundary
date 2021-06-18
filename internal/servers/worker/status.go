package worker

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/resolver"
)

// In the future we could make this configurable
const (
	statusInterval           = 2 * time.Second
	statusTimeout            = 10 * time.Second
	defaultStatusGracePeriod = 30 * time.Second
	statusGracePeriodEnvVar  = "BOUNDARY_STATUS_GRACE_PERIOD"
)

// statusGracePeriod returns the status grace period setting for this
// worker, in seconds.
//
// The grace period is the length of time we allow connections to run
// on a worker in the event of an error sending status updates. The
// period is defined the length of time since the last successful
// update.
//
// The setting is derived from one of the following:
//
//   * BOUNDARY_STATUS_GRACE_PERIOD, if defined, can be set to an
//   integer value to define the setting.
//   * If this is missing, the default (30 seconds) is used.
//
func (w *Worker) statusGracePeriod() time.Duration {
	if v := os.Getenv(statusGracePeriodEnvVar); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			w.logger.Error("could not read setting for BOUNDARY_STATUS_GRACE_PERIOD, using default",
				"err", err,
				"value", v,
			)
			return defaultStatusGracePeriod
		}

		if n < 1 {
			w.logger.Error("invalid setting for BOUNDARY_STATUS_GRACE_PERIOD, using default", "value", v)
			return defaultStatusGracePeriod
		}

		return time.Second * time.Duration(n)
	}

	return defaultStatusGracePeriod
}

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
			w.cleanupConnections(
				cancelCtx,
				cleanupConnectionsConditionNotAnyStatus(
					pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
					pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
				),
			)
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
			switch request.GetRequestType() {
			case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE:
				switch request.GetJob().GetType() {
				case pbs.JOBTYPE_JOBTYPE_SESSION:
					sessInfo := request.GetJob().GetSessionInfo()
					sessionId := sessInfo.GetSessionId()
					siRaw, ok := w.sessionInfoMap.Load(sessionId)
					if !ok {
						w.logger.Warn("asked to cancel session but could not find a local information for it", "session_id", sessionId)
						continue
					}
					si := siRaw.(*sessionInfo)
					si.Lock()
					si.status = sessInfo.GetStatus()
					si.Unlock()
				}
			}
		}
	}

	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(
		cancelCtx,
		cleanupConnectionsConditionAnyStatus(
			pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
		),
		cleanupConnectionsConditionExpired,
	)
}

type cleanupConnectionsCondition func(si *sessionInfo) bool

func cleanupConnectionsConditionAnyStatus(statuses ...services.SESSIONSTATUS) cleanupConnectionsCondition {
	return func(si *sessionInfo) bool {
		for _, status := range statuses {
			if si.status == status {
				return true
			}
		}

		return false
	}
}

func cleanupConnectionsConditionNotAnyStatus(statuses ...services.SESSIONSTATUS) cleanupConnectionsCondition {
	return func(si *sessionInfo) bool {
		var result bool
		for _, status := range statuses {
			if si.status == status {
				result = true
			}
		}

		return !result
	}
}

func cleanupConnectionsConditionExpired(si *sessionInfo) bool {
	return time.Until(si.lookupSessionResponse.Expiration.AsTime()) < 0
}

// cleanupConnections walks all sessions and shuts down connections
// based on the specified criteria. Additionally, sessions without
// connections are cleaned up from the local worker's state.
//
// Conditions are inclusive (OR); keep this in mind when working with
// the function.
func (w *Worker) cleanupConnections(cancelCtx context.Context, conditions ...cleanupConnectionsCondition) {
	closeInfo := make(map[string]string)
	cleanSessionIds := make([]string, 0)
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		si := value.(*sessionInfo)
		si.Lock()
		defer si.Unlock()
		var condMatched bool
		for _, cond := range conditions {
			if cond(si) {
				condMatched = true
			}
		}

		if !condMatched {
			// early exit, basically continue
			return true
		}

		var toClose int
		for k, v := range si.connInfoMap {
			if v.closeTime.IsZero() {
				toClose++
				v.connCancel()
				w.logger.Info("terminated connection due to cancellation or expiration", "session_id", si.id, "connection_id", k)
				closeInfo[k] = si.id
			}
		}
		// closeTime is marked by closeConnections iff the
		// status is returned for that connection as closed. If
		// the session is no longer valid and all connections
		// are marked closed, clean up the session.
		if toClose == 0 {
			cleanSessionIds = append(cleanSessionIds, si.id)
		}

		return true
	})

	// Note that we won't clean these from the info map until the
	// next time we run this function
	if len(closeInfo) > 0 {
		w.closeConnections(cancelCtx, closeInfo)
	}

	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	for _, v := range cleanSessionIds {
		w.sessionInfoMap.Delete(v)
	}
}

func (w *Worker) lastSuccessfulStatusTime() time.Time {
	lastStatus := w.LastStatusSuccess()
	if lastStatus == nil {
		return w.workerStartTime.Load().(time.Time)
	}

	return lastStatus.StatusTime
}

func (w *Worker) isPastGrace() (bool, time.Time, time.Duration) {
	t := w.lastSuccessfulStatusTime()
	u := w.statusGracePeriod()
	v := time.Since(t)
	return v > u, t, u
}
