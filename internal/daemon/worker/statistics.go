// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

func (w *Worker) startStatisticsTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startStatisticsTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "status ticking shutting down")
			return

		case <-timer.C:
			w.sendWorkerStatistics(cancelCtx)
			// Add a bit of jitter to the wait, so we aren't always getting,
			// status updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(common.StatisticsInterval + getRandomInterval(r))
		}
	}
}

func (w *Worker) sendWorkerStatistics(cancelCtx context.Context) {
	const op = "worker.(Worker).sendWorkerStatistics"
	w.confLock.Lock()
	defer w.confLock.Unlock()

	// Range over known sessions and collect info
	var sessionStats []*pbs.SessionStatistics
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
		var stats pbs.SessionStatistics
		localConnections := s.GetLocalConnections()
		stats.SessionId = s.GetId()
		for k, v := range localConnections {
			stats.Connections = append(stats.Connections, &pbs.ConnectionStatistics{
				ConnectionId: k,
				BytesUp:      v.BytesUp(),
				BytesDown:    v.BytesDown(),
			})
		}
		sessionStats = append(sessionStats, &stats)
		return true
	})

	ctx, cancel := context.WithTimeout(cancelCtx, time.Duration(w.statisticsCallTimeoutDuration.Load()))
	defer cancel()
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	_, err := client.Statistics(ctx, &pbs.StatisticsRequest{
		WorkerId: w.LastStatusSuccess().WorkerId,
		Sessions: sessionStats,
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making statistics request to controller", "controller_address", clientCon.Target()))
		return
	}
}
