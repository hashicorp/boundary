package worker

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/kr/pretty"
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc

	controllerConns []services.WorkerServiceClient
}

func New(conf *Config) (*Worker, error) {
	c := &Worker{
		conf:            conf,
		logger:          conf.Logger.Named("worker"),
		controllerConns: make([]services.WorkerServiceClient, 0, 3),
	}
	if conf.RawConfig.Worker == nil {
		panic(pretty.Sprint(conf.RawConfig))
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

	return c, nil
}

func (c *Worker) Start() error {
	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := c.startControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}
	return nil
}

func (c *Worker) Shutdown() error {
	c.baseCancel()
	if err := c.stopListeners(); err != nil {
		return fmt.Errorf("error stopping worker listeners: %w", err)
	}
	return nil
}
