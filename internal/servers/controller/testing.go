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
	addrs  []string // The address the Controller API is listening on
	client *api.Client
	ctx    context.Context
	cancel context.CancelFunc
}

// Controller returns the underlying controller
func (tc *TestController) Controller() *Controller {
	return tc.c
}

func (tc *TestController) Config() *Config {
	return tc.c.conf
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

func (tc *TestController) ApiAddrs() []string {
	if tc.addrs != nil {
		return tc.addrs
	}

	for _, listener := range tc.b.Listeners {
		if listener.Config.Purpose[0] == "api" {
			tcpAddr, ok := listener.Mux.Addr().(*net.TCPAddr)
			if !ok {
				tc.t.Fatal("could not parse address as a TCP addr")
			}
			addr := fmt.Sprintf("http://%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
			tc.addrs = append(tc.addrs, addr)
		}
	}

	return tc.addrs
}

func (tc *TestController) buildClient() {
	client, err := api.NewClient(nil)
	if err != nil {
		tc.t.Fatal(fmt.Errorf("error creating client: %w", err))
	}
	apiAddrs := tc.ApiAddrs()
	if len(apiAddrs) == 0 {
		tc.t.Fatal("no API addresses found")
	}
	if err := client.SetAddr(apiAddrs[0]); err != nil {
		tc.t.Fatal(fmt.Errorf("error setting client address: %w", err))
	}
	if tc.b.DefaultOrgId != "" {
		client.SetScopeId(tc.b.DefaultOrgId)
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

	// DefaultAuthMethodId is the default auth method ID to use, if set.
	DefaultAuthMethodId string

	// DefaultUsername is the username used when creating the default account.
	DefaultUsername string

	// DefaultPassword is the password used when creating the default account.
	DefaultPassword string

	// DisableDatabaseCreation can be set true to disable creating a dev
	// database
	DisableDatabaseCreation bool

	// If set, instead of creating a dev database, it will connect to an
	// existing database given the url
	DatabaseUrl string

	// If true, the controller will not be started
	DisableAutoStart bool

	// DisableAuthorizationFailures will still cause authz checks to be
	// performed but they won't cause 403 Forbidden. Useful for API-level
	// testing to avoid a lot of faff.
	DisableAuthorizationFailures bool
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
	if opts.DefaultAuthMethodId != "" {
		tc.b.DevAuthMethodId = opts.DefaultAuthMethodId
	}
	if opts.DefaultUsername != "" {
		tc.b.DevUsername = opts.DefaultUsername
	}
	if opts.DefaultPassword != "" {
		tc.b.DevPassword = opts.DefaultPassword
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
	if err := tc.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"api", "cluster", "worker-tls-alpn"}); err != nil {
		t.Fatal(err)
	}

	if !opts.DisableDatabaseCreation {
		if opts.DatabaseUrl != "" {
			if err := tc.b.ConnectToDatabase("postgres", opts.DatabaseUrl); err != nil {
				t.Fatal(err)
			}
		}
		if err := tc.b.CreateDevDatabase("postgres"); err != nil {
			t.Fatal(err)
		}
	}

	conf := &Config{
		RawConfig:                    opts.Config,
		Server:                       tc.b,
		DisableAuthorizationFailures: opts.DisableAuthorizationFailures,
	}

	tc.c, err = New(conf)
	if err != nil {
		tc.Shutdown()
		t.Fatal(err)
	}

	tc.buildClient()

	if !opts.DisableAutoStart {
		if err := tc.c.Start(); err != nil {
			tc.Shutdown()
			t.Fatal(err)
		}
	}

	return tc
}
