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
	"github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

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
	sessions := []*servers.SessionStatistics{}
	w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
		localConnections := s.GetLocalConnections()
		connections := make([]*servers.ConnectionStatistics, 0, len(localConnections))
		for connectionId, conn := range localConnections {
			connections = append(connections, &servers.ConnectionStatistics{
				ConnectionId: connectionId,
				BytesUp:      conn.BytesUp(),
				BytesDown:    conn.BytesDown(),
			})
		}
		sessions = append(sessions, &servers.SessionStatistics{
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
	return nil
}
