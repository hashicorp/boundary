package controller

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

// TestController wraps a base.Server and Controller to provide a
// fully-programmatic controller for tests. Error checking (for instance, for
// valid config) is not stringent at the moment.
type TestController struct {
	b            *base.Server
	c            *Controller
	t            *testing.T
	apiAddrs     []string // The address the Controller API is listening on
	clusterAddrs []string
	client       *api.Client
	ctx          context.Context
	cancel       context.CancelFunc
	name         string
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

func (tc *TestController) Name() string {
	return tc.name
}

func (tc *TestController) ApiAddrs() []string {
	return tc.addrs("api")
}

func (tc *TestController) ClusterAddrs() []string {
	return tc.addrs("cluster")
}

func (tc *TestController) addrs(purpose string) []string {
	var prefix string
	switch purpose {
	case "api":
		if tc.apiAddrs != nil {
			return tc.apiAddrs
		}
		prefix = "http://"
	case "cluster":
		if tc.clusterAddrs != nil {
			return tc.clusterAddrs
		}
	}

	addrs := make([]string, 0, len(tc.b.Listeners))
	for _, listener := range tc.b.Listeners {
		if listener.Config.Purpose[0] == purpose {
			tcpAddr, ok := listener.Mux.Addr().(*net.TCPAddr)
			if !ok {
				tc.t.Fatal("could not parse address as a TCP addr")
			}
			addr := fmt.Sprintf("%s%s:%d", prefix, tcpAddr.IP.String(), tcpAddr.Port)
			addrs = append(addrs, addr)
		}
	}

	switch purpose {
	case "api":
		tc.apiAddrs = addrs
	case "cluster":
		tc.clusterAddrs = addrs
	}

	return addrs
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
		if err := tc.c.Shutdown(false); err != nil {
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

	// The controller KMS to use, or one will be created
	ControllerKMS wrapping.Wrapper

	// The worker auth KMS to use, or one will be created
	WorkerAuthKMS wrapping.Wrapper

	// The name to use for the controller, otherwise one will be randomly
	// generated, unless provided in a non-nil Config
	Name string

	// The logger to use, or one will be created
	Logger hclog.Logger
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
		opts.Config.Controller.Name = opts.Name
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
	tc.b.Logger = opts.Logger
	if tc.b.Logger == nil {
		tc.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
		})
	}

	if opts.Config.Controller.Name == "" {
		opts.Config.Controller.Name, err = base62.Random(5)
		if err != nil {
			t.Fatal(err)
		}
		tc.b.Logger.Info("controller name generated", "name", opts.Config.Controller.Name)
	}
	tc.name = opts.Config.Controller.Name

	// Set up KMSes
	switch {
	case opts.ControllerKMS != nil && opts.WorkerAuthKMS != nil:
		tc.b.ControllerKMS = opts.ControllerKMS
		tc.b.WorkerAuthKMS = opts.WorkerAuthKMS
	case opts.ControllerKMS == nil && opts.WorkerAuthKMS == nil:
		if err := tc.b.SetupKMSes(nil, opts.Config.SharedConfig, []string{"controller", "worker-auth"}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("either controller and worker auth KMS must both be set, or neither")
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tc.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"api", "cluster"}); err != nil {
		t.Fatal(err)
	}

	if opts.DatabaseUrl != "" {
		tc.b.DatabaseUrl = opts.DatabaseUrl
		if err := tc.b.ConnectToDatabase("postgres"); err != nil {
			t.Fatal(err)
		}
	} else if !opts.DisableDatabaseCreation {
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

func (tc *TestController) AddClusterControllerMember(t *testing.T, opts *TestControllerOpts) *TestController {
	if opts == nil {
		opts = new(TestControllerOpts)
	}
	nextOpts := &TestControllerOpts{
		DatabaseUrl:   tc.c.conf.DatabaseUrl,
		ControllerKMS: tc.c.conf.ControllerKMS,
		WorkerAuthKMS: tc.c.conf.WorkerAuthKMS,
		Name:          opts.Name,
		Logger:        tc.c.conf.Logger,
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
		nextOpts.Logger.Info("controller name generated", "name", nextOpts.Name)
	}
	return NewTestController(t, nextOpts)
}
