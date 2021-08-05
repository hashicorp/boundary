package controller

import (
	"context"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// In the future we could make this configurable
const (
	statusInterval      = 10 * time.Second
	terminationInterval = 1 * time.Minute
)

// This is exported so it can be tweaked in tests
var RecoveryNonceCleanupInterval = 2 * time.Minute

func (c *Controller) startStatusTicking(cancelCtx context.Context) {
	const op = "controller.(Controller).startStatusTicking"
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "status ticking shutting down")
			return

		case <-timer.C:
			server := &servers.Server{
				PrivateId:   c.conf.RawConfig.Controller.Name,
				Name:        c.conf.RawConfig.Controller.Name,
				Type:        resource.Controller.String(),
				Description: c.conf.RawConfig.Controller.Description,
				Address:     c.conf.RawConfig.Controller.PublicClusterAddr,
			}
			repo, err := c.ServersRepoFn()
			if err != nil {
				event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error fetching repository for status update"))
			} else {
				_, _, err = repo.UpsertServer(cancelCtx, server)
				if err != nil {
					event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error performing status update"))
				} else {
				}
			}
			timer.Reset(statusInterval)
		}
	}
}

func (c *Controller) startRecoveryNonceCleanupTicking(cancelCtx context.Context) {
	const op = "controller.(Controller).startRecoveryNonceCleanupTicking"
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "recovery nonce ticking shutting down")
			return

		case <-timer.C:
			repo, err := c.ServersRepoFn()
			if err != nil {
				event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error fetching repository for recovery nonce cleanup"))
			} else {
				nonceCount, err := repo.CleanupNonces(cancelCtx)
				if err != nil {
					event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error performing recovery nonce cleanup"))
				} else if nonceCount > 0 {
					event.WriteSysEvent(cancelCtx, op, "recovery nonce cleanup successful", "nonces_cleaned", nonceCount)
				}
			}
			timer.Reset(RecoveryNonceCleanupInterval)
		}
	}
}

func (c *Controller) startTerminateCompletedSessionsTicking(cancelCtx context.Context) {
	const op = "controller.(Controller).startTerminateCompletedSessionsTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// desynchronize calls from the controllers, to ease the load on the DB.
	getRandomInterval := func() time.Duration {
		// 0 to 0.5 adjustment to the base
		f := r.Float64() / 2
		// Half a chance to be faster, not slower
		if r.Float32() > 0.5 {
			f = -1 * f
		}
		return terminationInterval + time.Duration(f*float64(time.Minute))
	}
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "terminating completed sessions ticking shutting down")
			return

		case <-timer.C:
			repo, err := c.SessionRepoFn()
			if err != nil {
				event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error fetching repository for terminating completed sessions"))
			} else {
				terminationCount, err := repo.TerminateCompletedSessions(cancelCtx)
				if err != nil {
					event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error performing termination of completed sessions"))
				} else if terminationCount > 0 {
				}
			}
			timer.Reset(getRandomInterval())
		}
	}
}

func (c *Controller) startCloseExpiredPendingTokens(cancelCtx context.Context) {
	const op = "controller.(Controller).startCloseExpiredPendingTokens"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// desynchronize calls from the controllers, to ease the load on the DB.
	getRandomInterval := func() time.Duration {
		// 0 to 0.5 adjustment to the base
		f := r.Float64() / 2
		// Half a chance to be faster, not slower
		if r.Float32() > 0.5 {
			f = -1 * f
		}
		return terminationInterval + time.Duration(f*float64(time.Minute))
	}
	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "closing expired pending tokens ticking shutting down")
			return

		case <-timer.C:
			repo, err := c.AuthTokenRepoFn()
			if err != nil {
				event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error fetching repository for closing expired pending tokens"))
			} else {
				closeCount, err := repo.CloseExpiredPendingTokens(cancelCtx)
				if err != nil {
					event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error performing closing expired pending tokens"))
				} else if closeCount > 0 {
					event.WriteSysEvent(cancelCtx, op, "closing expired pending tokens completed sessions successful", "pending_tokens_closed", closeCount)
				}
			}
			timer.Reset(getRandomInterval())
		}
	}
}
