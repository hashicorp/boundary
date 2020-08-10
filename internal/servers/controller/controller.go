package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/patrickmn/go-cache"
	ua "go.uber.org/atomic"
)
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     ua.Bool

	workerAuthCache *cache.Cache

	// Used for testing
	workerStatusUpdateTimes *sync.Map

	// Repo factory methods
	IamRepoFn          common.IamRepoFactory
	StaticHostRepoFn   common.StaticRepoFactory
	AuthTokenRepoFn    common.AuthTokenRepoFactory
	ServersRepoFn      common.ServersRepoFactory
	PasswordAuthRepoFn common.PasswordAuthRepoFactory

	clusterAddress string
}

func New(conf *Config) (*Controller, error) {
	c := &Controller{
		conf:                    conf,
		logger:                  conf.Logger.Named("controller"),
		workerStatusUpdateTimes: new(sync.Map),
	}

	c.started.Store(false)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Controller == nil {
		conf.RawConfig.Controller = new(config.Controller)
	}
	if conf.RawConfig.Controller.Name == "" {
		if conf.RawConfig.Controller.Name, err = base62.Random(10); err != nil {
			return nil, fmt.Errorf("error auto-generating controller name: %w", err)
		}
	}

	if !conf.RawConfig.DisableMlock {
		// Ensure our memory usage is locked into physical RAM
		if err := mlock.LockMemory(); err != nil {
			return nil, fmt.Errorf(
				"Failed to lock memory: %v\n\n"+
					"This usually means that the mlock syscall is not available.\n"+
					"Boundary uses mlock to prevent memory from being swapped to\n"+
					"disk. This requires root privileges as well as a machine\n"+
					"that supports mlock. Please enable mlock on your system or\n"+
					"disable Boundary from using it. To disable Boundary from using it,\n"+
					"set the `disable_mlock` configuration option in your configuration\n"+
					"file.",
				err)
		}
	}

	// Set up repo stuff
	dbase := db.New(c.conf.Database)
	c.IamRepoFn = func() (*iam.Repository, error) {
		return iam.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	}
	c.StaticHostRepoFn = func() (*static.Repository, error) {
		return static.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	}
	c.AuthTokenRepoFn = func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	}
	c.ServersRepoFn = func() (*servers.Repository, error) {
		return servers.NewRepository(c.logger.Named("servers.repository"), dbase, dbase, c.conf.ControllerKMS)
	}
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	}

	c.workerAuthCache = cache.New(0, 0)

	return c, nil
}

func (c *Controller) Start() error {
	if c.started.Load() {
		c.logger.Info("already started, skipping")
		return nil
	}
	c.baseContext, c.baseCancel = context.WithCancel(context.Background())

	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting controller listeners: %w", err)
	}

	c.startStatusTicking(c.baseContext)
	c.started.Store(true)

	return nil
}

func (c *Controller) Shutdown(serversOnly bool) error {
	if !c.started.Load() {
		c.logger.Info("already shut down, skipping")
		return nil
	}
	c.baseCancel()
	if err := c.stopListeners(serversOnly); err != nil {
		return fmt.Errorf("error stopping controller listeners: %w", err)
	}
	c.clusterAddress = ""
	c.started.Store(false)
	return nil
}

// WorkerStatusUpdateTimes returns the map, which specifically is held in _this_
// controller, not the DB. It's used in tests to verify that a given controller
// is receiving updates from an expected set of workers, to test out balancing
// and auto reconnection.
func (c *Controller) WorkerStatusUpdateTimes() *sync.Map {
	return c.workerStatusUpdateTimes
}
