package controller

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
)

type Controller struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc

	// Repos
	IamRepo *iam.Repository
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
					"Watchtower uses mlock to prevent memory from being swapped to\n"+
					"disk. This requires root privileges as well as a machine\n"+
					"that supports mlock. Please enable mlock on your system or\n"+
					"disable Watchtower from using it. To disable Watchtower from using it,\n"+
					"set the `disable_mlock` configuration option in your configuration\n"+
					"file.",
				err)
		}
	}

	c.baseContext, c.baseCancel = context.WithCancel(context.Background())

	// Set up repo stuff
	var err error

	dbase := db.New(c.conf.Database)
	c.IamRepo, err = iam.NewRepository(dbase, dbase, c.conf.ControllerKMS)
	if err != nil {
		return nil, fmt.Errorf("unable to create iam repo: %w", err)
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
