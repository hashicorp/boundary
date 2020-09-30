package controller

import (
	"context"
	"math/rand"
	"time"

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
	go func() {
		timer := time.NewTimer(0)
		for {
			select {
			case <-cancelCtx.Done():
				c.logger.Info("status ticking shutting down")
				return

			case <-timer.C:
				server := &servers.Server{
					PrivateId:   c.conf.RawConfig.Controller.Name,
					Name:        c.conf.RawConfig.Controller.Name,
					Type:        resource.Controller.String(),
					Description: c.conf.RawConfig.Controller.Description,
					Address:     c.clusterAddress,
				}
				repo, err := c.ServersRepoFn()
				if err != nil {
					c.logger.Error("error fetching repository for status update", "error", err)
				} else {
					_, _, err = repo.UpsertServer(cancelCtx, server)
					if err != nil {
						c.logger.Error("error performing status update", "error", err)
					} else {
						c.logger.Trace("controller status successfully saved")
					}
				}
				timer.Reset(statusInterval)
			}
		}
	}()
}

func (c *Controller) startRecoveryNonceCleanupTicking(cancelCtx context.Context) {
	go func() {
		timer := time.NewTimer(0)
		for {
			select {
			case <-cancelCtx.Done():
				c.logger.Info("recovery nonce ticking shutting down")
				return

			case <-timer.C:
				repo, err := c.ServersRepoFn()
				if err != nil {
					c.logger.Error("error fetching repository for recovery nonce cleanup", "error", err)
				} else {
					nonceCount, err := repo.CleanupNonces(cancelCtx)
					if err != nil {
						c.logger.Error("error performing recovery nonce cleanup", "error", err)
					} else if nonceCount > 0 {
						c.logger.Info("recovery nonce cleanup successful", "nonces_cleaned", nonceCount)
					}
				}
				timer.Reset(RecoveryNonceCleanupInterval)
			}
		}
	}()
}

func (c *Controller) startTerminateCompletedSessionsTicking(cancelCtx context.Context) {
	go func() {
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
				c.logger.Info("terminating completed sessions ticking shutting down")
				return

			case <-timer.C:
				repo, err := c.SessionRepoFn()
				if err != nil {
					c.logger.Error("error fetching repository for terminating completed sessions", "error", err)
				} else {
					terminationCount, err := repo.TerminateCompletedSessions(cancelCtx)
					if err != nil {
						c.logger.Error("error performing termination of completed sessions", "error", err)
					} else if terminationCount > 0 {
						c.logger.Info("terminating completed sessions successful", "sessions_terminated", terminationCount)
					}
				}
				timer.Reset(getRandomInterval())
			}
		}
	}()
}
