// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	stderr "errors"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// lastSessionInfo holds the last successful session info RPC time.
type lastSessionInfo struct {
	LastSuccessfulRequestTime time.Time
}

func (w *Worker) startSessionInfoTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startSessionInfoTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "session infor ticking shutting down")
			return
		case <-timer.C:
			err := w.sendSessionInfo(cancelCtx)
			if err != nil {
				event.WriteError(w.baseContext, op, err)
			}
			// Add a bit of jitter to the wait, so we aren't always getting,
			// session information updates at the exact same intervals, to
			// ease the load on the DB.
			timer.Reset(w.sessionInfoInterval + getRandomInterval(r))
		}
	}
}

func (w *Worker) sendSessionInfo(cancelCtx context.Context) error {
	const op = "worker.(Worker).sendSessionInfo"
	// skip when the workerId is not available
	if w.LastRoutingInfoSuccess() == nil {
		return errors.New(cancelCtx, errors.Internal, op, "missing latest routing info")
	}
	workerId := w.LastRoutingInfoSuccess().GetWorkerId()
	if workerId == "" {
		return errors.New(cancelCtx, errors.Internal, op, "worker id is empty")
	}

	var recordedSessionIds []string
	if w.recorderManager != nil {
		recSessIds, err := w.recorderManager.SessionsManaged(cancelCtx)
		if err != nil {
			event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error getting session ids from recorderManager"))
		}
		if len(recSessIds) != 0 {
			recordedSessionIds = append(recordedSessionIds, recSessIds...)
		}
	}

	var activeSessions []*pbs.Session
	for _, sessionId := range recordedSessionIds {
		activeSessions = append(activeSessions, &pbs.Session{
			SessionId:     sessionId,
			SessionType:   pbs.SessionType_SESSION_TYPE_RECORDED,
			SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		})
	}
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
		activeSessions = append(activeSessions, &pbs.Session{
			SessionId:     s.GetId(),
			SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
			SessionStatus: s.GetStatus(),
		})
		return true
	})
	// skip when there are no sessions to report
	if len(activeSessions) == 0 {
		return nil
	}
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	sessionInfoCtx, statusCancel := context.WithTimeout(cancelCtx, time.Duration(w.sessionInfoCallTimeoutDuration.Load()))
	defer statusCancel()
	result, err := client.SessionInfo(sessionInfoCtx, &pbs.SessionInfoRequest{
		WorkerId: workerId,
		Sessions: activeSessions,
	})
	if err != nil {
		if isPastGrace, lastSessionInfoTime, gracePeriod := w.isPastSessionInfoGrace(); isPastGrace {
			event.WriteError(cancelCtx, op,
				stderr.New("session information error grace period has expired, canceling all sessions on worker"),
				event.WithInfo("last_session_info_time", lastSessionInfoTime.String(), "grace_period", gracePeriod),
			)
			// Cancel connections if grace period has expired. These Connections will be closed in the
			// database on the next successful status report, or via the Controller’s dead Worker cleanup connections job.
			w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
				for _, connId := range s.CancelAllLocalConnections() {
					event.WriteSysEvent(cancelCtx, op, "terminated connection due to session information grace period expiration", "session_id", s.GetId(), "connection_id", connId)
				}
				return true
			})
		}
		return errors.Wrap(cancelCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("error making session information request to controller: controller_address: %s", clientCon.Target()))
	}

	w.lastSessionInfoSuccess.Store(&lastSessionInfo{
		LastSuccessfulRequestTime: time.Now(),
	})

	var nonActiveRecordedSessionIds []string
	for _, s := range result.GetNonActiveSessions() {
		switch s.GetSessionType() {
		case pbs.SessionType_SESSION_TYPE_RECORDED:
			if s.SessionStatus != pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE {
				nonActiveRecordedSessionIds = append(nonActiveRecordedSessionIds, s.GetSessionId())
			}
		case pbs.SessionType_SESSION_TYPE_INGRESSED:
			sessionId := s.GetSessionId()
			managedSession := w.sessionManager.Get(sessionId)
			if managedSession == nil {
				event.WriteError(cancelCtx, op, stderr.New("session change requested but could not find local information for it"), event.WithInfo("session_id", sessionId))
				continue
			}
			managedSession.ApplyLocalStatus(s.GetSessionStatus())
			// Update connection state if there are any connections in the request.
			for _, c := range s.GetConnections() {
				if err := managedSession.ApplyLocalConnectionStatus(c.GetConnectionId(), c.GetStatus()); err != nil {
					event.WriteError(cancelCtx, op, err, event.WithInfo("connection_id", c.GetConnectionId()))
				}
			}
		}
	}
	if w.recorderManager != nil {
		if err := w.recorderManager.ReauthorizeAllExcept(cancelCtx, nonActiveRecordedSessionIds); err != nil {
			event.WriteError(cancelCtx, op, err)
		}
	}
	// Standard cleanup: Run through current jobs. Cancel connections
	// for any canceling session or any session that is expired.
	w.cleanupConnections(cancelCtx, false, w.sessionManager)
	return nil
}

func (w *Worker) isPastSessionInfoGrace() (bool, time.Time, time.Duration) {
	t := w.workerStartTime
	info := w.lastSessionInfoSuccess.Load().(*lastSessionInfo)
	if info != nil {
		t = info.LastSuccessfulRequestTime
	}
	u := time.Duration(w.successfulSessionInfoGracePeriod.Load())
	v := time.Since(t)
	return v > u, t, u
}

// cleanupConnections walks all sessions and shuts down all proxy connections.
// After the local connections are terminated, they are requested to be marked
// closed on the controller.
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
