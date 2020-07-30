package controller

import (
	"time"

	"github.com/hashicorp/watchtower/internal/servers"
	"github.com/hashicorp/watchtower/internal/types/resource"
)

// In the future we could make this configurable
const (
	statusInterval = 10 * time.Second
)

func (c *Controller) startStatusTicking() {
	go func() {
		timer := time.NewTimer(statusInterval)
		for {
			select {
			case <-c.baseContext.Done():
				c.logger.Info("status ticking shutting down")
				return
			case <-timer.C:
				server := &servers.Server{
					PrivateId:   c.conf.RawConfig.Controller.Name,
					Name:        c.conf.RawConfig.Controller.Name,
					Type:        resource.Controller.String(),
					Description: c.conf.RawConfig.Controller.Description,
				}
				repo, err := c.ServersRepoFn()
				if err != nil {
					c.logger.Error("error fetching repository for status update", "error", err)
				} else {
					_, _, err = repo.Upsert(c.baseContext, server)
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
