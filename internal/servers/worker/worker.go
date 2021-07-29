package worker

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg sync.WaitGroup

	controllerStatusConn *atomic.Value
	lastStatusSuccess    *atomic.Value
	workerStartTime      time.Time

	controllerResolver *atomic.Value

	controllerSessionConn *atomic.Value
	sessionInfoMap        *sync.Map

	// We store the current set in an atomic value so that we can add
	// reload-on-sighup behavior later
	tags *atomic.Value
	// This stores whether or not to send updated tags on the next status
	// request. It can be set via startup in New below, or (eventually) via
	// SIGHUP.
	updateTags ua.Bool
}

func New(conf *Config) (*Worker, error) {
	w := &Worker{
		conf:                  conf,
		logger:                conf.Logger.Named("worker"),
		started:               ua.NewBool(false),
		controllerStatusConn:  new(atomic.Value),
		lastStatusSuccess:     new(atomic.Value),
		controllerResolver:    new(atomic.Value),
		controllerSessionConn: new(atomic.Value),
		sessionInfoMap:        new(sync.Map),
		tags:                  new(atomic.Value),
	}

	w.lastStatusSuccess.Store((*LastStatusInformation)(nil))
	w.controllerResolver.Store((*manual.Resolver)(nil))

	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}

	w.ParseAndStoreTags(conf.RawConfig.Worker.Tags)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Worker.Name, err = w.conf.RawConfig.Worker.InitNameIfEmpty(); err != nil {
		return nil, fmt.Errorf("error auto-generating worker name: %w", err)
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

	return w, nil
}

func (w *Worker) Start() error {
	const op = "worker.(Worker).Start"
	if w.started.Load() {
		event.WriteSysEvent(context.TODO(), op, "already started, skipping")
		return nil
	}

	w.baseContext, w.baseCancel = context.WithCancel(context.Background())

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.controllerResolver.Store(controllerResolver)

	if err := w.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := w.startControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}

	w.tickerWg.Add(1)
	go func() {
		defer w.tickerWg.Done()
		w.startStatusTicking(w.baseContext)
	}()

	w.workerStartTime = time.Now()
	w.started.Store(true)

	return nil
}

// Shutdown shuts down the workers. skipListeners can be used to not stop
// listeners, useful for tests if we want to stop and start a worker. In order
// to create new listeners we'd have to migrate listener setup logic here --
// doable, but work for later.
func (w *Worker) Shutdown(skipListeners bool) error {
	const op = "worker.(Worker).Shutdown"
	if !w.started.Load() {
		event.WriteSysEvent(context.TODO(), op, "already shut down, skipping")
		return nil
	}

	// Stop listeners first to prevent new connections to the
	// controller.
	w.logger.Debug("beginning shutdown")
	defer w.started.Store(false)
	w.Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})
	w.baseCancel()
	if !skipListeners {
		w.logger.Debug("stopping listeners")
		if err := w.stopListeners(); err != nil {
			return fmt.Errorf("error stopping worker listeners: %w", err)
		}
	}

	// Shut down all connections.
	w.logger.Debug("shutting down all connections due to worker shutdown or reload")
	w.cleanupConnections(w.baseContext, true)

	// Wait for next status request to succeed. Don't wait too long;
	// wrap the base context in a timeout equal to our status grace
	// period.
	w.logger.Debug("waiting for next status report to controller")
	waitStatusStart := time.Now()
	nextStatusCtx, nextStatusCancel := context.WithTimeout(w.baseContext, w.conf.StatusGracePeriodDuration)
	defer nextStatusCancel()
	for {
		if err := nextStatusCtx.Err(); err != nil {
			w.logger.Error("error waiting for next status report to controller", "err", err)
			break
		}

		if w.lastSuccessfulStatusTime().Sub(waitStatusStart) > 0 {
			break
		}

		time.Sleep(time.Second)
	}

	// Proceed with remainder of shutdown.
	w.logger.Debug("canceling base context and shutting down connection to controller")
	w.baseCancel()
	w.Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})

	w.started.Store(false)
	w.tickerWg.Wait()
	if w.conf.Eventer != nil {
		if err := w.conf.Eventer.FlushNodes(context.Background()); err != nil {
			return fmt.Errorf("error flushing worker eventer nodes: %w", err)
		}
	}

	w.logger.Debug("shutdown successful")
	return nil
}

func (w *Worker) Resolver() *manual.Resolver {
	raw := w.controllerResolver.Load()
	if raw == nil {
		panic("nil resolver")
	}
	return raw.(*manual.Resolver)
}

func (w *Worker) ParseAndStoreTags(incoming map[string][]string) {
	if len(incoming) == 0 {
		w.tags.Store(map[string]*servers.TagValues{})
		return
	}
	tags := make(map[string]*servers.TagValues, len(incoming))
	for k, v := range incoming {
		tags[k] = &servers.TagValues{
			Values: append(make([]string, 0, len(v)), v...),
		}
	}
	w.tags.Store(tags)
	w.updateTags.Store(true)
}
