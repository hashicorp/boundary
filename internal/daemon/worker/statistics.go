// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// lastStatistics holds the last successful statistics RPC time.
type lastStatistics struct {
	LastSuccessfulRequestTime time.Time
}

func (w *Worker) startStatisticsTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startStatisticsTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "statistics ticking shutting down")
			return
		case <-timer.C:
			err := w.sendStatistic(cancelCtx)
			if err != nil {
				event.WriteError(w.baseContext, op, err)
			}
			// Add a bit of jitter to the wait, so we aren't always getting,
			// statistics updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(common.StatisticsInterval + getRandomInterval(r))
		}
	}
}

func (w *Worker) sendStatistic(cancelCtx context.Context) error {
	const op = "worker.(Worker).sendStatistic"
	// skip when the workerId is not available
	if w.LastStatusSuccess() == nil {
		return errors.New(cancelCtx, errors.Internal, op, "missing latest status")
	}
	workerId := w.LastStatusSuccess().GetWorkerId()
	if workerId == "" {
		return errors.New(cancelCtx, errors.Internal, op, "worker id is empty")
	}
	sessions := []*pbs.SessionStatistics{}
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
		localConnections := s.GetLocalConnections()
		connections := make([]*pbs.Connection, 0, len(localConnections))
		for connectionId, conn := range localConnections {
			connections = append(connections, &pbs.Connection{
				ConnectionId: connectionId,
				BytesUp:      conn.BytesUp(),
				BytesDown:    conn.BytesDown(),
				Status:       conn.Status,
			})
		}
		sessions = append(sessions, &pbs.SessionStatistics{
			SessionId:   s.GetId(),
			Connections: connections,
		})
		return true
	})
	// skip when there are no sessions to report
	if len(sessions) == 0 {
		return nil
	}
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	statisticsCtx, statusCancel := context.WithTimeout(cancelCtx, time.Duration(w.statisticsCallTimeoutDuration.Load()))
	defer statusCancel()
	_, err := client.Statistics(statisticsCtx, &pbs.StatisticsRequest{
		WorkerId: workerId,
		Sessions: sessions,
	})
	if err != nil {
		return errors.Wrap(cancelCtx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("error making statistics request to controller: controller_address: %s", clientCon.Target()))
	}

	w.lastStatisticsSuccess.Store(&lastStatistics{
		LastSuccessfulRequestTime: time.Now(),
	})

	return nil
}

// WaitForNextSuccessfulStatisticsUpdate waits for the next successful statistics. It's
// used by testing in place of a more opaque and possibly unnecessarily long sleep for
// things like initial controller check-in, etc.
//
// The timeout is aligned with twice the worker's statistics timeout duration. A nil error
// means the statistics was sent successfully.
func (w *Worker) WaitForNextSuccessfulStatisticsUpdate() error {
	const op = "worker.(Worker).WaitForNextSuccessfulStatisticsUpdate"
	waitStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, time.Duration(2*w.statisticsCallTimeoutDuration.Load()))
	defer cancel()
	event.WriteSysEvent(ctx, op, "waiting for next statistics report to controller")
	for {
		select {
		case <-time.After(time.Second):
			// pass

		case <-ctx.Done():
			event.WriteError(ctx, op, ctx.Err(), event.WithInfoMsg("error waiting for next statistics report to controller"))
			return ctx.Err()
		}

		si := w.lastStatisticsSuccess.Load().(*lastStatistics)
		if si != nil && si.LastSuccessfulRequestTime.After(waitStart) {
			break
		}
	}

	event.WriteSysEvent(ctx, op, "next worker statistics update sent successfully")
	return nil
}
