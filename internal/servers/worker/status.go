package worker

import (
	"math/rand"
	"time"

	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"google.golang.org/grpc/resolver"
)

// In the future we could make this configurable
const (
	statusInterval = 2 * time.Second
)

func (w *Worker) startStatusTicking() {
	go func() {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		// This function exists to desynchronize calls to controllers from
		// workers so we aren't always getting status updates at the exact same
		// intervals, to ease the load on the DB.
		getRandomInterval := func() time.Duration {
			// 0 to 0.5 adjustment to the base
			f := r.Float64() / 2
			// Half a chance to be faster, not slower
			if r.Float32() > 0.5 {
				f = -1 * f
			}
			return statusInterval + time.Duration(f*float64(time.Second))
		}

		timer := time.NewTimer(0)
		for {
			select {
			case <-w.baseContext.Done():
				w.logger.Info("status ticking shutting down")
				return

			case <-timer.C:
				for _, c := range w.controllerConns {
					result, err := c.client.Status(w.baseContext, &pbs.StatusRequest{
						Worker: &servers.Server{
							PrivateId:   w.conf.RawConfig.Worker.Name,
							Name:        w.conf.RawConfig.Worker.Name,
							Type:        resource.Worker.String(),
							Description: w.conf.RawConfig.Worker.Description,
							Address:     w.listeningAddress,
						},
					})
					if err != nil {
						w.logger.Error("error making status request to controller", "controller_addr_", c.controllerAddr, "error", err)
					} else {
						w.logger.Trace("successfully sent status to controller", "controller_addr", c.controllerAddr)
						addrs := make([]resolver.Address, 0, len(result.Controllers))
						strAddrs := make([]string, 0, len(result.Controllers))
						for _, v := range result.Controllers {
							addrs = append(addrs, resolver.Address{Addr: v.Address})
							strAddrs = append(strAddrs, v.Address)
						}
						w.controllerResolver.UpdateState(resolver.State{Addresses: addrs})
						w.logger.Trace("found controllers", "addresses", strAddrs)
						w.lastStatusSuccess.Store(time.Now())
					}
				}
				timer.Reset(getRandomInterval())
			}
		}
	}()
}

func (w *Worker) LastStatusSuccess() time.Time {
	return w.lastStatusSuccess.Load().(time.Time)
}
