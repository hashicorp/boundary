package worker

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

// TestWorker wraps a base.Server and Worker to provide a
// fully-programmatic worker for tests. Error checking (for instance, for
// valid config) is not stringent at the moment.
type TestWorker struct {
	b      *base.Server
	w      *Worker
	t      *testing.T
	addrs  []string // The address the worker proxies are listening on
	ctx    context.Context
	cancel context.CancelFunc
	name   string
}

// Worker returns the underlying controller
func (tw *TestWorker) Worker() *Worker {
	return tw.w
}

func (tw *TestWorker) Config() *Config {
	return tw.w.conf
}

func (tw *TestWorker) Context() context.Context {
	return tw.ctx
}

func (tw *TestWorker) Cancel() {
	tw.cancel()
}

func (tw *TestWorker) Name() string {
	return tw.name
}

func (tw *TestWorker) ControllerAddrs() []string {
	var addrs []string
	tw.w.controllerConns.Range(func(_, v interface{}) bool {
		// If something is removed from the map while ranging, ignore it
		if v == nil {
			return true
		}
		c := v.(*controllerConnection)
		addrs = append(addrs, c.controllerAddr)
		return true
	})

	return addrs
}

func (tw *TestWorker) ProxyAddrs() []string {
	if tw.addrs != nil {
		return tw.addrs
	}

	for _, listener := range tw.b.Listeners {
		if listener.Config.Purpose[0] == "worker-alpn-tls" {
			tcpAddr, ok := listener.Mux.Addr().(*net.TCPAddr)
			if !ok {
				tw.t.Fatal("could not parse address as a TCP addr")
			}
			addr := fmt.Sprintf("%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
			tw.addrs = append(tw.addrs, addr)
		}
	}

	return tw.addrs
}

// Shutdown runs any cleanup functions; be sure to run this after your test is
// done
func (tw *TestWorker) Shutdown() {
	if tw.b != nil {
		close(tw.b.ShutdownCh)
	}

	tw.cancel()

	if tw.w != nil {
		if err := tw.w.Shutdown(false); err != nil {
			tw.t.Error(err)
		}
	}
	if tw.b != nil {
		if err := tw.b.RunShutdownFuncs(); err != nil {
			tw.t.Error(err)
		}
	}
}

type TestWorkerOpts struct {
	// Config; if not provided a dev one will be created
	Config *config.Config

	// Sets initial controller addresses
	InitialControllers []string

	// If true, the worker will not be started
	DisableAutoStart bool

	// The worker auth KMS to use, or one will be created
	WorkerAuthKMS wrapping.Wrapper

	// The name to use for the worker, otherwise one will be randomly
	// generated, unless provided in a non-nil Config
	Name string

	// The logger to use, or one will be created
	Logger hclog.Logger
}

func NewTestWorker(t *testing.T, opts *TestWorkerOpts) *TestWorker {
	ctx, cancel := context.WithCancel(context.Background())

	tw := &TestWorker{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	if opts == nil {
		opts = new(TestWorkerOpts)
	}

	// Base server
	tw.b = base.NewServer(nil)
	tw.b.Command = &base.Command{
		ShutdownCh: make(chan struct{}),
	}

	// Get dev config, or use a provided one
	var err error
	if opts.Config == nil {
		opts.Config, err = config.DevWorker()
		if err != nil {
			t.Fatal(err)
		}
		opts.Config.Worker.Name = opts.Name
	}

	if len(opts.InitialControllers) > 0 {
		opts.Config.Worker.Controllers = opts.InitialControllers
	}

	// Start a logger
	tw.b.Logger = opts.Logger
	if tw.b.Logger == nil {
		tw.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
		})
	}

	if opts.Config.Worker == nil {
		opts.Config.Worker = new(config.Worker)
	}
	if opts.Config.Worker.Name == "" {
		opts.Config.Worker.Name, err = base62.Random(5)
		if err != nil {
			t.Fatal(err)
		}
		tw.b.Logger.Info("worker name generated", "name", opts.Config.Worker.Name)
	}
	tw.name = opts.Config.Worker.Name

	// Set up KMSes
	switch {
	case opts.WorkerAuthKMS != nil:
		tw.b.WorkerAuthKMS = opts.WorkerAuthKMS
	default:
		if err := tw.b.SetupKMSes(nil, opts.Config.SharedConfig, []string{"worker-auth"}); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tw.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"worker-alpn-tls"}); err != nil {
		t.Fatal(err)
	}

	conf := &Config{
		RawConfig: opts.Config,
		Server:    tw.b,
	}

	tw.w, err = New(conf)
	if err != nil {
		tw.Shutdown()
		t.Fatal(err)
	}

	if !opts.DisableAutoStart {
		if err := tw.w.Start(); err != nil {
			tw.Shutdown()
			t.Fatal(err)
		}
	}

	return tw
}

func (tw *TestWorker) AddClusterWorkerMember(t *testing.T, opts *TestWorkerOpts) *TestWorker {
	if opts == nil {
		opts = new(TestWorkerOpts)
	}
	nextOpts := &TestWorkerOpts{
		WorkerAuthKMS:      tw.w.conf.WorkerAuthKMS,
		Name:               opts.Name,
		InitialControllers: tw.ControllerAddrs(),
		Logger:             tw.w.conf.Logger,
	}
	if opts.Logger != nil {
		nextOpts.Logger = opts.Logger
	}
	if nextOpts.Name == "" {
		var err error
		nextOpts.Name, err = base62.Random(5)
		if err != nil {
			t.Fatal(err)
		}
		nextOpts.Logger.Info("worker name generated", "name", nextOpts.Name)
	}
	return NewTestWorker(t, nextOpts)
}
