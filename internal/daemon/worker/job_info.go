// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

type LastJobInfo struct {
	*pbs.JobInfoResponse
	JobInfoTime time.Time
}

// LastJobInfoSuccess reports the last time we sent a successful
// session route info request.
func (w *Worker) LastJobInfoSuccess() *LastJobInfo {
	s, ok := w.lastJobInfoSuccess.Load().(*LastJobInfo)
	if !ok {
		return nil
	}
	return s
}

func (w *Worker) startJobInfoTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startJobInfoTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "session route info ticking shutting down")
			return

		case <-timer.C:
			w.sendJobInfo(cancelCtx)
			// Add a bit of jitter to the wait, so we aren't always getting,
			// status updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(common.JobInfoInterval + getRandomInterval(r))
		}
	}
}

func (w *Worker) sendJobInfo(cancelCtx context.Context) {
	const op = "worker.(Worker).sendJobInfo"
	w.confLock.Lock()
	defer w.confLock.Unlock()

	// Collect the different session ids that are being monitored by this worker
	var monitoredSessionIds []string

	if w.recorderManager != nil {
		recSessIds, err := w.recorderManager.SessionsManaged(cancelCtx)
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
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
		status := s.GetStatus()
		sessionId := s.GetId()
		localConnections := s.GetLocalConnections()
		connections := make([]*pbs.Connection, 0, len(localConnections))
		for k, v := range localConnections {
			connections = append(connections, &pbs.Connection{
				ConnectionId: k,
				Status:       v.Status,
			})
		}
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

	ctx, cancel := context.WithTimeout(cancelCtx, time.Duration(w.jobInfoCallTimeoutDuration.Load()))
	defer cancel()
	// Send status information
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	result, err := client.JobInfo(ctx, &pbs.JobInfoRequest{
		WorkerId: w.LastStatusSuccess().WorkerId,
		Jobs:     activeJobs,
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making job info request to controller", "controller_address", clientCon.Target()))
		return
	}

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
				si := w.sessionManager.Get(sessionId)
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
	if w.recorderManager != nil {
		if err := w.recorderManager.ReauthorizeAllExcept(cancelCtx, nonActiveMonitoredSessionIds); err != nil {
			event.WriteError(cancelCtx, op, err)
		}
	}

	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(cancelCtx, false)

	// Store the new route info after updating the addresses so that it can compare to the old route info first
	w.lastJobInfoSuccess.Store(&LastJobInfo{JobInfoResponse: result, JobInfoTime: time.Now()})
}

// cleanupConnections walks all sessions and shuts down all proxy connections.
// After the local connections are terminated, they are requested to be marked
// close on the controller.
// Additionally, sessions without connections are cleaned up from the
// local worker's state.
//
// Use ignoreSessionState to ignore the state checks, this closes all
// connections, regardless of whether or not the session is still active.
func (w *Worker) cleanupConnections(cancelCtx context.Context, ignoreSessionState bool) {
	const op = "worker.(Worker).cleanupConnections"
	closeInfo := make(map[string]*session.ConnectionCloseData)
	cleanSessionIds := make([]string, 0)
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
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
		_ = w.sessionManager.RequestCloseConnections(cancelCtx, closeInfo)
	}
	// Forget sessions where the session is expired/canceled and all
	// connections are canceled and marked closed
	w.sessionManager.DeleteLocalSession(cleanSessionIds)
}
