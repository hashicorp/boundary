package controller

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/mlock"
)

type Controller struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc

	// Repo factory methods
	IamRepoFn        common.IamRepoFactory
	StaticHostRepoFn common.StaticRepoFactory
	AuthTokenRepoFn  common.AuthTokenRepoFactory

	PasswordAuthRepoFn common.PasswordAuthRepoFactory
}

func New(conf *Config) (*Controller, error) {
	c := &Controller{
		conf:   conf,
		logger: conf.Logger.Named("controller"),
	}

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
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

	c.baseContext, c.baseCancel = context.WithCancel(context.Background())

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
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	}

	return c, nil
}

func (c *Controller) Start() error {
	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting controller listeners: %w", err)
	}
	return nil
}

func (c *Controller) Shutdown() error {
	if err := c.stopListeners(); err != nil {
		return fmt.Errorf("error stopping controller listeners: %w", err)
	}
	return nil
}
