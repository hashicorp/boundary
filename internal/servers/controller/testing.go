package controller

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/jinzhu/gorm"
	"github.com/kr/pretty"
)

const (
	DefaultTestAuthMethodId = "ampw_1234567890"
	DefaultTestLoginName    = "user"
	DefaultTestPassword     = "passpass"
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
	opts         *TestControllerOpts
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

func (tc *TestController) IamRepo() *iam.Repository {
	repo, err := tc.c.IamRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) ServersRepo() *servers.Repository {
	repo, err := tc.c.ServersRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
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

func (tc *TestController) DbConn() *gorm.DB {
	return tc.b.Database
}

func (tc *TestController) Token() *authtokens.AuthToken {
	if tc.opts.DisableAuthMethodCreation {
		tc.t.Error("no default auth method ID configured")
		return nil
	}
	token, apiErr, err := authmethods.NewClient(tc.Client()).Authenticate(
		tc.Context(),
		tc.b.DevAuthMethodId,
		map[string]interface{}{
			"login_name": tc.b.DevLoginName,
			"password":   tc.b.DevPassword,
		},
	)
	if err != nil {
		tc.t.Error(fmt.Errorf("error logging in: %w", err))
		return nil
	}
	if apiErr != nil {
		tc.t.Error(fmt.Errorf("api err from logging in: %s", pretty.Sprint(apiErr)))
		return nil
	}
	return token.Item
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
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token to ensure we
	// understand the client state at the start of each test.
	client.SetToken("")

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
		if !tc.opts.DisableDatabaseDestruction {
			if tc.b.DestroyDevDatabase() != nil {
				if err := tc.b.DestroyDevDatabase(); err != nil {
					tc.t.Error(err)
				}
			}
		}
	}
}

type TestControllerOpts struct {
	// Config; if not provided a dev one will be created
	Config *config.Config

	// DefaultAuthMethodId is the default auth method ID to use, if set.
	DefaultAuthMethodId string

	// DefaultLoginName is the login name used when creating the default account.
	DefaultLoginName string

	// DefaultPassword is the password used when creating the default account.
	DefaultPassword string

	// DisableAuthMethodCreation can be set true to disable creating an auth
	// method automatically.
	DisableAuthMethodCreation bool

	// DisableDatabaseCreation can be set true to disable creating a dev
	// database
	DisableDatabaseCreation bool

	// DisableDatabaseDestruction can be set true to allow a database to be
	// created but examined after-the-fact
	DisableDatabaseDestruction bool

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
	RootKms wrapping.Wrapper

	// The worker auth KMS to use, or one will be created
	WorkerAuthKms wrapping.Wrapper

	// The recovery KMS to use, or one will be created
	RecoveryKms wrapping.Wrapper

	// Disables KMS key creation. Only valid when a database url is specified,
	// at the moment.
	DisableKmsKeyCreation bool

	// The name to use for the controller, otherwise one will be randomly
	// generated, unless provided in a non-nil Config
	Name string

	// The logger to use, or one will be created
	Logger hclog.Logger
}

func NewTestController(t *testing.T, opts *TestControllerOpts) *TestController {
	ctx, cancel := context.WithCancel(context.Background())

	if opts == nil {
		opts = new(TestControllerOpts)
	}

	tc := &TestController{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
		opts:   opts,
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

	if opts.DefaultAuthMethodId != "" {
		tc.b.DevAuthMethodId = opts.DefaultAuthMethodId
	} else {
		tc.b.DevAuthMethodId = DefaultTestAuthMethodId
	}
	if opts.DefaultLoginName != "" {
		tc.b.DevLoginName = opts.DefaultLoginName
	} else {
		tc.b.DevLoginName = DefaultTestLoginName
	}
	if opts.DefaultPassword != "" {
		tc.b.DevPassword = opts.DefaultPassword
	} else {
		tc.b.DevPassword = DefaultTestPassword
	}

	// Start a logger
	tc.b.Logger = opts.Logger
	if tc.b.Logger == nil {
		tc.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
		})
	}

	if opts.Config.Controller == nil {
		opts.Config.Controller = new(config.Controller)
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
	case opts.RootKms != nil && opts.WorkerAuthKms != nil:
		tc.b.RootKms = opts.RootKms
		tc.b.WorkerAuthKms = opts.WorkerAuthKms
	case opts.RootKms == nil && opts.WorkerAuthKms == nil:
		if err := tc.b.SetupKMSes(nil, opts.Config); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("either controller and worker auth KMS must both be set, or neither")
	}
	if opts.RecoveryKms != nil {
		tc.b.RecoveryKms = opts.RecoveryKms
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
		if err := db.InitStore("postgres", nil, tc.b.DatabaseUrl); err != nil {
			t.Fatal(err)
		}
		if err := tc.b.ConnectToDatabase("postgres"); err != nil {
			t.Fatal(err)
		}
		if !opts.DisableKmsKeyCreation {
			if err := tc.b.CreateGlobalKmsKeys(); err != nil {
				t.Fatal(err)
			}
		}
		if !opts.DisableAuthMethodCreation {
			if err := tc.b.CreateInitialAuthMethod(); err != nil {
				t.Fatal(err)
			}
		}
	} else if !opts.DisableDatabaseCreation {
		var createOpts []base.Option
		if opts.DisableAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipAuthMethodCreation())
		}
		if err := tc.b.CreateDevDatabase("postgres", createOpts...); err != nil {
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
		DatabaseUrl:               tc.c.conf.DatabaseUrl,
		DefaultAuthMethodId:       tc.c.conf.DevAuthMethodId,
		RootKms:                   tc.c.conf.RootKms,
		WorkerAuthKms:             tc.c.conf.WorkerAuthKms,
		RecoveryKms:               tc.c.conf.RecoveryKms,
		Name:                      opts.Name,
		Logger:                    tc.c.conf.Logger,
		DisableKmsKeyCreation:     true,
		DisableAuthMethodCreation: true,
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
