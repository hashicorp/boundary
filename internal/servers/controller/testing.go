package controller

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/config"
)

// TestController wraps a base.Server and Controller to provide a
// fully-programmatic controller for tests. Error checking (for instance, for
// valid config) is not stringent at the moment.
type TestController struct {
	b      *base.Server
	c      *Controller
	t      *testing.T
	addr   string // The address the Controller API is listening on
	client *api.Client
	ctx    context.Context
	cancel context.CancelFunc
}

// Controller returns the underlying controller
func (tc *TestController) Controller() *Controller {
	return tc.c
}

func (tc *TestController) Client() *api.Client {
	return tc.client
}

func (tc *TestController) Context() context.Context {
	return tc.ctx
}

func (tc *TestController) Cancel() {
	tc.cancel()
}

func (tc *TestController) ApiAddress() string {
	if tc.addr != "" {
		return tc.addr
	}
	var apiLn *base.ServerListener
	for _, listener := range tc.b.Listeners {
		if listener.Config.Purpose[0] == "api" {
			apiLn = listener
			break
		}
	}
	if apiLn == nil {
		tc.t.Fatal("could not find api listener")
	}

	tcpAddr, ok := apiLn.Mux.Addr().(*net.TCPAddr)
	if !ok {
		tc.t.Fatal("could not parse address as a TCP addr")
	}
	tc.addr = fmt.Sprintf("http://%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
	return tc.addr
}

func (tc *TestController) buildClient() {
	client, err := api.NewClient(nil)
	if err != nil {
		tc.t.Fatal(fmt.Errorf("error creating client: %w", err))
	}
	if err := client.SetAddr(tc.ApiAddress()); err != nil {
		tc.t.Fatal(fmt.Errorf("error setting client address: %w", err))
	}

	tc.client = client
}

// Shutdown runs any cleanup functions; be sure to run this after your test is
// done
func (tc *TestController) Shutdown() {
	if tc.b != nil {
		close(tc.b.ShutdownCh)
	}

	tc.cancel()

	if tc.c != nil {
		if err := tc.c.Shutdown(); err != nil {
			tc.t.Error(err)
		}
	}
	if tc.b != nil {
		if err := tc.b.RunShutdownFuncs(); err != nil {
			tc.t.Error(err)
		}
		if tc.b.DestroyDevDatabase() != nil {
			if err := tc.b.DestroyDevDatabase(); err != nil {
				tc.t.Error(err)
			}
		}
	}
}

type TestControllerOpts struct {
	// Config; if not provided a dev one will be created
	Config *config.Config

	// DefaultOrgId is the default org ID to use, if set. Can also be provided
	// in the normal config.
	DefaultOrgId string

	// DisableDatabaseCreation can be set true to disable creating a dev
	// database
	DisableDatabaseCreation bool
}

func NewTestController(t *testing.T, opts *TestControllerOpts) *TestController {
	ctx, cancel := context.WithCancel(context.Background())

	tc := &TestController{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	if opts == nil {
		opts = new(TestControllerOpts)
	}

	// Base server
	tc.b = base.NewServer(nil)
	tc.b.Command = &base.Command{
		ShutdownCh: make(chan struct{}),
	}

	// Get dev config, or use a provided one
	var err error
	if opts.Config == nil {
		opts.Config, err = config.DevController()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Set default org ID, preferring one passed in from opts over config
	if opts.Config.DefaultOrgId != "" {
		tc.b.DefaultOrgId = opts.Config.DefaultOrgId
	}
	if opts.DefaultOrgId != "" {
		tc.b.DefaultOrgId = opts.DefaultOrgId
	}

	// Start a logger
	tc.b.Logger = hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	// Set up KMSes
	if err := tc.b.SetupKMSes(nil, opts.Config.SharedConfig, []string{"controller", "worker-auth"}); err != nil {
		t.Fatal(err)
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tc.b.SetupListeners(nil, opts.Config.SharedConfig); err != nil {
		t.Fatal(err)
	}

	if !opts.DisableDatabaseCreation {
		if err := tc.b.CreateDevDatabase("postgres"); err != nil {
			t.Fatal(err)
		}
	}

	conf := &Config{
		RawConfig: opts.Config,
		Server:    tc.b,
	}

	tc.c, err = New(conf)
	if err != nil {
		tc.Shutdown()
		t.Fatal(err)
	}

	tc.buildClient()

	if err := tc.c.Start(); err != nil {
		tc.Shutdown()
		t.Fatal(err)
	}

	return tc
}
