// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/connectivity"
)

var firstStatusCheckPostHooks []func(context.Context, *Worker) error = []func(context.Context, *Worker) error{
	// Start session route info and statistics ticking after first status success
	func(ctx context.Context, w *Worker) error {
		w.tickerWg.Add(2)
		go func() {
			defer w.tickerWg.Done()
			w.startRoutingInfoTicking(w.baseContext)
		}()
		go func() {
			defer w.tickerWg.Done()
			w.startStatisticsTicking(w.baseContext)
		}()
		return nil
	},
}

var downstreamWorkersFactory func(ctx context.Context, workerId string, ver string) (downstreamers, error)

var checkHCPBUpstreams func(w *Worker) bool

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime time.Time
}

// getRandomInterval returns a duration in a random interval between -0.5 and 0.5 seconds (exclusive).
func getRandomInterval(r *rand.Rand) time.Duration {
	// 0 to 0.5 adjustment to the base
	f := r.Float64() / 2
	// Half a chance to be faster, not slower
	if r.Float32() > 0.5 {
		f = -1 * f
	}
	return time.Duration(f * float64(time.Second))
}

func (w *Worker) startStatusTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startStatusTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

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

			w.sendWorkerStatus(cancelCtx)
			// Add a bit of jitter to the wait, so we aren't always getting,
			// status updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(common.StatusInterval + getRandomInterval(r))
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

func (w *Worker) sendWorkerStatus(cancelCtx context.Context) {
	const op = "worker.(Worker).sendWorkerStatus"
	w.confLock.Lock()
	defer w.confLock.Unlock()

	keyId := w.WorkerAuthCurrentKeyId.Load()
	switch {
	case w.conf.RawConfig.Worker.Name == "" && keyId == "":
		event.WriteError(cancelCtx, op, errors.New("worker name and keyId are both empty; at least one is needed to identify a worker"),
			event.WithInfoMsg("error making status request to controller"))
		return
	}

	// Send status information
	versionInfo := version.Get()
	// Send status information
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	statusCtx, statusCancel := context.WithTimeout(cancelCtx, time.Duration(w.statusCallTimeoutDuration.Load()))
	defer statusCancel()
	result, err := client.Status(statusCtx, &pbs.StatusRequest{
		KeyId:          keyId,
		WorkerId:       w.LastStatusSuccess().WorkerId,
		ReleaseVersion: versionInfo.FullVersionNumber(false),
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making status request to controller", "controller_address", clientCon.Target()))
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
			w.sessionManager.ForEachLocalSession(func(s session.Session) bool {
				for _, connId := range s.CancelAllLocalConnections() {
					event.WriteSysEvent(cancelCtx, op, "terminated connection due to status grace period expiration", "session_id", s.GetId(), "connection_id", connId)
				}
				return true
			})

			// In the case that the control plane has gone down and come up with different IPs,
			// append initial upstreams/ cluster addr to the resolver to try
			if w.GrpcClientConn.Load().GetState() == connectivity.TransientFailure {
				lastRouteInfo := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
				if lastRouteInfo != nil && lastRouteInfo.LastCalculatedUpstreams != nil {
					addrs := lastRouteInfo.LastCalculatedUpstreams

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
					if slices.Equal(lastRouteInfo.LastCalculatedUpstreams, addrs) {
						// Nothing to update
						return
					}

					w.updateAddresses(cancelCtx, addrs)
					lastRouteInfo.LastCalculatedUpstreams = addrs
					w.lastRoutingInfoSuccess.Store(lastRouteInfo)
				}
			}

			// Exit out of status function; our work here is done and we don't need to create closeConnection requests
			return
		}

		// Standard cleanup: Run through current jobs. Cancel connections
		// for any canceling session or any session that is expired.
		w.cleanupConnections(cancelCtx, false)
		return
	}

	w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now()})

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
