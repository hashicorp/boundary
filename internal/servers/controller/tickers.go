package controller

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// In the future we could make this configurable
const (
	statusInterval = 10 * time.Second
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
