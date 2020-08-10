package worker

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/watchtower/internal/cmd/config"
	"google.golang.org/grpc/resolver/manual"
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc

	controllerConns   *sync.Map
	lastStatusSuccess *atomic.Value

	listeningAddress string

	controllerResolver        *manual.Resolver
	controllerResolverCleanup func()
}

func New(conf *Config) (*Worker, error) {
	w := &Worker{
		conf:              conf,
		logger:            conf.Logger.Named("worker"),
		controllerConns:   new(sync.Map),
		lastStatusSuccess: new(atomic.Value),
	}

	w.lastStatusSuccess.Store(time.Time{})

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}
	if conf.RawConfig.Worker.Name == "" {
		if conf.RawConfig.Worker.Name, err = base62.Random(10); err != nil {
			return nil, fmt.Errorf("error auto-generating worker name: %w", err)
		}
	}

	w.controllerResolver, w.controllerResolverCleanup = manual.GenerateAndRegisterManualResolver()

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

	w.baseContext, w.baseCancel = context.WithCancel(context.Background())

	return w, nil
}

func (w *Worker) Start() error {
	if err := w.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := w.startControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}
	w.startStatusTicking()
	return nil
}

func (w *Worker) Shutdown() error {
	w.controllerResolverCleanup()
	w.baseCancel()
	if err := w.stopListeners(); err != nil {
		return fmt.Errorf("error stopping worker listeners: %w", err)
	}
	return nil
}
