package worker

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/base62"
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
	lastStatus := tw.w.LastStatusSuccess()
	for _, v := range lastStatus.GetControllers() {
		addrs = append(addrs, v.Address)
	}

	return addrs
}

func (tw *TestWorker) ProxyAddrs() []string {
	if tw.addrs != nil {
		return tw.addrs
	}

	for _, listener := range tw.b.Listeners {
		if listener.Config.Purpose[0] == "proxy" {
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

// TestSessionInfo provides detail about a particular session from
// the worker's local session state. This detail is a point-in-time
// snapshot of what's in sessionInfoMap for a particular session, and
// may not contain all of the information that is contained within
// it, or the underlying ConnInfoMap. Only details that are really
// important to testing are passed along.
type TestSessionInfo struct {
	Id     string
	Status pbs.SESSIONSTATUS

	// Connections is indexed by connection ID, which is also included
	// within TestConnectionInfo for convenience.
	Connections map[string]TestConnectionInfo
}

// TestConnectionInfo provides detail about a particular connection
// as a part of TestSessionInfo. See that struct for details about
// the purpose of this data and how it's gathered.
type TestConnectionInfo struct {
	Id        string
	Status    pbs.CONNECTIONSTATUS
	CloseTime time.Time
}

// LookupSession returns session info from the worker's local session
// state.
//
// The return boolean will be true if the session was found, false if
// it wasn't.
//
// See TestSessionInfo for details on how to use this info.
func (tw *TestWorker) LookupSession(id string) (TestSessionInfo, bool) {
	var result TestSessionInfo
	raw, ok := tw.w.sessionInfoMap.Load(id)
	if !ok {
		return result, false
	}

	sess := raw.(*session.Info)
	sess.RLock()
	defer sess.RUnlock()

	conns := make(map[string]TestConnectionInfo)
	for _, conn := range sess.ConnInfoMap {
		conns[conn.Id] = TestConnectionInfo{
			Id:        conn.Id,
			Status:    conn.Status,
			CloseTime: conn.CloseTime,
		}
	}

	result.Id = sess.Id
	result.Status = sess.Status
	result.Connections = conns

	return result, true
}

// Shutdown runs any cleanup functions; be sure to run this after your test is
// done
func (tw *TestWorker) Shutdown() {
	if tw.b != nil {
		close(tw.b.ShutdownCh)
	}

	tw.cancel()

	if tw.w != nil {
		if err := tw.w.Shutdown(); err != nil {
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
	WorkerAuthKms wrapping.Wrapper

	// The name to use for the worker, otherwise one will be randomly
	// generated, unless provided in a non-nil Config
	Name string

	// The logger to use, or one will be created
	Logger hclog.Logger

	// The amount of time to wait before marking connections as closed when a
	// connection cannot be made back to the controller
	StatusGracePeriodDuration time.Duration

	// Whether to set the replay value
	EnableAuthReplay bool
}

func NewTestWorker(t *testing.T, opts *TestWorkerOpts) *TestWorker {
	const op = "worker.NewTestWorker"
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

	// Initialize status grace period
	tw.b.SetStatusGracePeriodDuration(opts.StatusGracePeriodDuration)

	if opts.Config.Worker == nil {
		opts.Config.Worker = new(config.Worker)
	}
	if opts.Config.Worker.Name == "" {
		opts.Config.Worker.Name, err = opts.Config.Worker.InitNameIfEmpty()
		if err != nil {
			t.Fatal(err)
		}
		event.WriteSysEvent(ctx, op, "worker name generated", "name", opts.Config.Worker.Name)
	}
	tw.name = opts.Config.Worker.Name

	if err := tw.b.SetupEventing(tw.b.Logger, tw.b.StderrLock, opts.Config.Worker.Name, base.WithEventerConfig(opts.Config.Eventing)); err != nil {
		t.Fatal(err)
	}

	// Set up KMSes
	switch {
	case opts.WorkerAuthKms != nil:
		tw.b.WorkerAuthKms = opts.WorkerAuthKms
	default:
		if err := tw.b.SetupKMSes(tw.b.Context, nil, opts.Config); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tw.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"proxy"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.b.SetupWorkerPublicAddress(opts.Config, ""); err != nil {
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

	if opts.EnableAuthReplay {
		tw.w.testReuseAuthNonces = true
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
	const op = "worker.(TestWorker).AddClusterWorkerMember"
	if opts == nil {
		opts = new(TestWorkerOpts)
	}
	nextOpts := &TestWorkerOpts{
		WorkerAuthKms:             tw.w.conf.WorkerAuthKms,
		Name:                      opts.Name,
		InitialControllers:        tw.ControllerAddrs(),
		Logger:                    tw.w.conf.Logger,
		StatusGracePeriodDuration: opts.StatusGracePeriodDuration,
	}
	if nextOpts.Name == "" {
		var err error
		nextOpts.Name, err = base62.Random(5)
		if err != nil {
			t.Fatal(err)
		}
		event.WriteSysEvent(context.TODO(), op, "worker name generated", "name", nextOpts.Name)
	}
	return NewTestWorker(t, nextOpts)
}
