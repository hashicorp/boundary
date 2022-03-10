package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/gen/testing/interceptor"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const (
	DefaultOrgId                             = "o_1234567890"
	DefaultProjectId                         = "p_1234567890"
	DefaultTestPasswordAuthMethodId          = "ampw_1234567890"
	DefaultTestOidcAuthMethodId              = "amoidc_1234567890"
	DefaultTestLoginName                     = "admin"
	DefaultTestUnprivilegedLoginName         = "user"
	DefaultTestPassword                      = "passpass"
	DefaultTestUserId                        = "u_1234567890"
	DefaultTestPasswordAccountId             = intglobals.NewPasswordAccountPrefix + "_1234567890"
	DefaultTestOidcAccountId                 = "acctoidc_1234567890"
	DefaultTestUnprivilegedPasswordAccountId = intglobals.NewPasswordAccountPrefix + "_0987654321"
	DefaultTestUnprivilegedOidcAccountId     = "acctoidc_0987654321"
	DefaultTestPluginId                      = "pl_1234567890"
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

// Server returns the underlying base server
func (tc *TestController) Server() *base.Server {
	return tc.b
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

func (tc *TestController) Kms() *kms.Kms {
	return tc.c.kms
}

func (tc *TestController) IamRepo() *iam.Repository {
	repo, err := tc.c.IamRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) AuthTokenRepo() *authtoken.Repository {
	repo, err := tc.c.AuthTokenRepoFn()
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

func (tc *TestController) DbConn() *db.DB {
	return tc.b.Database
}

func (tc *TestController) Logger() hclog.Logger {
	return tc.b.Logger
}

func (tc *TestController) Token() *authtokens.AuthToken {
	if tc.opts.DisableAuthMethodCreation {
		tc.t.Error("no default auth method ID configured")
		return nil
	}
	result, err := authmethods.NewClient(tc.Client()).Authenticate(
		tc.Context(),
		tc.b.DevPasswordAuthMethodId,
		"login",
		map[string]interface{}{
			"login_name": tc.b.DevLoginName,
			"password":   tc.b.DevPassword,
		},
	)
	if err != nil {
		tc.t.Error(fmt.Errorf("error logging in: %w", err))
		return nil
	}
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
		tc.t.Error(fmt.Errorf("error unmarshaling token: %w", err))
		return nil
	}
	return token
}

func (tc *TestController) UnprivilegedToken() *authtokens.AuthToken {
	if tc.opts.DisableAuthMethodCreation {
		tc.t.Error("no default auth method ID configured")
		return nil
	}
	result, err := authmethods.NewClient(tc.Client()).Authenticate(
		tc.Context(),
		tc.b.DevPasswordAuthMethodId,
		"login",
		map[string]interface{}{
			"login_name": tc.b.DevUnprivilegedLoginName,
			"password":   tc.b.DevUnprivilegedPassword,
		},
	)
	if err != nil {
		tc.t.Error(fmt.Errorf("error logging in: %w", err))
		return nil
	}
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
		tc.t.Error(fmt.Errorf("error unmarshaling token: %w", err))
		return nil
	}
	return token
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
			addr := listener.Mux.Addr()
			switch {
			case strings.HasPrefix(addr.String(), "/"):
				switch purpose {
				case "api":
					addrs = append(addrs, fmt.Sprintf("unix://%s", addr.String()))
				default:
					addrs = append(addrs, addr.String())
				}
			default:
				tcpAddr, ok := addr.(*net.TCPAddr)
				if !ok {
					tc.t.Fatal("could not parse address as a TCP addr")
				}
				addr := fmt.Sprintf("%s%s", prefix, net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)))
				addrs = append(addrs, addr)
			}
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
		if err := tc.c.Shutdown(); err != nil {
			tc.t.Error(err)
		}
	}
	if tc.b != nil {
		if err := tc.b.RunShutdownFuncs(); err != nil {
			tc.t.Error(err)
		}
		if !tc.opts.DisableDatabaseDestruction {
			if tc.b.DestroyDevDatabase(tc.ctx) != nil {
				if err := tc.b.DestroyDevDatabase(tc.ctx); err != nil {
					tc.t.Error(err)
				}
			}
		}
	}
}

type TestControllerOpts struct {
	// ConfigHcl is the HCL to be parsed to generate the initial config.
	// Overrides Config if both are set.
	ConfigHcl string

	// Config; if not provided a dev one will be created, unless ConfigHcl is
	// set.
	Config *config.Config

	// DefaultPasswordAuthMethodId is the default password method ID to use, if set.
	DefaultPasswordAuthMethodId string

	// DefaultOidcAuthMethodId is the default OIDC method ID to use, if set.
	DefaultOidcAuthMethodId string

	// DefaultLoginName is the login name used when creating the default admin account.
	DefaultLoginName string

	// DefaultUnprivilegedLoginName is the login name used when creating the default unprivileged account.
	DefaultUnprivilegedLoginName string

	// DefaultPassword is the password used when creating the default accounts.
	DefaultPassword string

	// DisableInitialLoginRoleCreation can be set true to disable creating the
	// global scope login role automatically.
	DisableInitialLoginRoleCreation bool

	// DisableAuthMethodCreation can be set true to disable creating an auth
	// method automatically.
	DisableAuthMethodCreation bool

	// DisableOidcAuthMethodCreation can be set true to disable the built-in
	// OIDC listener. Useful for e.g. unix listener tests.
	DisableOidcAuthMethodCreation bool

	// DisableScopesCreation can be set true to disable creating scopes
	// automatically.
	DisableScopesCreation bool

	// DisableHostResourcesCreation can be set true to disable creating a host
	// catalog and related resources automatically.
	DisableHostResourcesCreation bool

	// DisableTargetCreation can be set true to disable creating a target
	// automatically.
	DisableTargetCreation bool

	// DisableDatabaseCreation can be set true to disable creating a dev
	// database
	DisableDatabaseCreation bool

	// DisableDatabaseDestruction can be set true to allow a database to be
	// created but examined after-the-fact
	DisableDatabaseDestruction bool

	// DatabaseUrl will cause the test controller to connect to an existing
	// database given the url instead of creating a new one
	DatabaseUrl string

	// DisableDatabaseTemplate forces using a fresh Postgres instance in Docker
	// instead of using a local templated version. Useful for CI of external
	// repos, like Terraform.
	DisableDatabaseTemplate bool

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

	// The suffix to use for initial resources
	InitialResourcesSuffix string

	// The logger to use, or one will be created
	Logger hclog.Logger

	// A cluster address for overriding the advertised controller listener
	// (overrides address provided in config, if any)
	PublicClusterAddr string

	// The amount of time to wait before marking connections as closed when a
	// worker has not reported in
	StatusGracePeriodDuration time.Duration

	// The amount of time between the scheduler waking up to run it's registered
	// jobs.
	SchedulerRunJobInterval time.Duration
}

func NewTestController(t *testing.T, opts *TestControllerOpts) *TestController {
	const op = "controller.NewTestController"
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

	conf := TestControllerConfig(t, ctx, tc, opts)
	var err error
	tc.c, err = New(ctx, conf)
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

// TestControllerConfig provides a way to create a config for a TestController.
// The tc passed as a parameter will be modified by this func.
func TestControllerConfig(t *testing.T, ctx context.Context, tc *TestController, opts *TestControllerOpts) *Config {
	const op = "controller.TestControllerConfig"
	if opts == nil {
		opts = new(TestControllerOpts)
	}

	// Base server
	tc.b = base.NewServer(&base.Command{
		Context:    ctx,
		ShutdownCh: make(chan struct{}),
	})

	// Get dev config, or use a provided one
	var err error
	switch {
	case opts.ConfigHcl != "":
		cfg, err := config.Parse(opts.ConfigHcl)
		if err != nil {
			t.Fatal(err)
		}
		opts.Config = cfg

	case opts.Config == nil:
		opts.Config, err = config.DevController()
		if err != nil {
			t.Fatal(err)
		}
		opts.Config.Controller.Name = opts.Name
	}

	if opts.DefaultPasswordAuthMethodId != "" {
		tc.b.DevPasswordAuthMethodId = opts.DefaultPasswordAuthMethodId
	} else {
		tc.b.DevPasswordAuthMethodId = DefaultTestPasswordAuthMethodId
	}
	if opts.DefaultOidcAuthMethodId != "" {
		tc.b.DevOidcAuthMethodId = opts.DefaultOidcAuthMethodId
	} else {
		tc.b.DevOidcAuthMethodId = DefaultTestOidcAuthMethodId
	}
	if opts.DefaultLoginName != "" {
		tc.b.DevLoginName = opts.DefaultLoginName
	} else {
		tc.b.DevLoginName = DefaultTestLoginName
	}
	if opts.DefaultUnprivilegedLoginName != "" {
		tc.b.DevUnprivilegedLoginName = opts.DefaultUnprivilegedLoginName
	} else {
		tc.b.DevUnprivilegedLoginName = DefaultTestUnprivilegedLoginName
	}
	if opts.DefaultPassword != "" {
		tc.b.DevPassword = opts.DefaultPassword
		tc.b.DevUnprivilegedPassword = opts.DefaultPassword
	} else {
		tc.b.DevPassword = DefaultTestPassword
		tc.b.DevUnprivilegedPassword = DefaultTestPassword
	}
	tc.b.DevOrgId = DefaultOrgId
	tc.b.DevProjectId = DefaultProjectId
	tc.b.DevPasswordAccountId = DefaultTestPasswordAccountId
	tc.b.DevOidcAccountId = DefaultTestOidcAccountId
	tc.b.DevUnprivilegedPasswordAccountId = DefaultTestUnprivilegedPasswordAccountId
	tc.b.DevUnprivilegedOidcAccountId = DefaultTestUnprivilegedOidcAccountId
	tc.b.DevLoopbackHostPluginId = DefaultTestPluginId

	tc.b.EnabledPlugins = append(tc.b.EnabledPlugins, base.EnabledPluginHostLoopback)

	// Start a logger
	tc.b.Logger = opts.Logger
	if tc.b.Logger == nil {
		tc.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
			Mutex: tc.b.StderrLock,
		})
	}

	if opts.Config.Controller == nil {
		opts.Config.Controller = new(config.Controller)
	}
	if opts.Config.Controller.Name == "" {
		opts.Config.Controller.Name, err = opts.Config.Controller.InitNameIfEmpty()
		if err != nil {
			t.Fatal(err)
		}
	}
	opts.Config.Controller.SchedulerRunJobInterval = opts.SchedulerRunJobInterval

	if err := tc.b.SetupEventing(tc.b.Logger, tc.b.StderrLock, opts.Config.Controller.Name, base.WithEventerConfig(opts.Config.Eventing)); err != nil {
		t.Fatal(err)
	}

	// Initialize status grace period
	tc.b.SetStatusGracePeriodDuration(opts.StatusGracePeriodDuration)

	tc.name = opts.Config.Controller.Name

	if opts.InitialResourcesSuffix != "" {
		suffix := opts.InitialResourcesSuffix
		tc.b.DevPasswordAuthMethodId = "ampw_" + suffix
		tc.b.DevOidcAuthMethodId = "amoidc_" + suffix
		tc.b.DevHostCatalogId = "hcst_" + suffix
		tc.b.DevHostId = "hst_" + suffix
		tc.b.DevHostSetId = "hsst_" + suffix
		tc.b.DevOrgId = "o_" + suffix
		tc.b.DevProjectId = "p_" + suffix
		tc.b.DevTargetId = "ttcp_" + suffix
		tc.b.DevUserId = "u_" + suffix
		tc.b.DevUnprivilegedUserId = "u_" + strutil.Reverse(strings.TrimPrefix(tc.b.DevUserId, "u_"))
	} else {
		tc.b.DevUserId = DefaultTestUserId
	}
	tc.b.DevUnprivilegedUserId = "u_" + strutil.Reverse(strings.TrimPrefix(tc.b.DevUserId, "u_"))

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
	if err := tc.b.SetupControllerPublicClusterAddress(opts.Config, ""); err != nil {
		t.Fatal(err)
	}

	// Set cluster address if we supplied one (overrides one in config)
	if opts.PublicClusterAddr != "" {
		opts.Config.Controller.PublicClusterAddr = opts.PublicClusterAddr
	}

	if opts.DatabaseUrl != "" {
		tc.b.DatabaseUrl = opts.DatabaseUrl
		if _, err := schema.MigrateStore(ctx, "postgres", tc.b.DatabaseUrl); err != nil {
			t.Fatal(err)
		}
		if err := tc.b.ConnectToDatabase(tc.ctx, "postgres"); err != nil {
			t.Fatal(err)
		}
		if !opts.DisableKmsKeyCreation {
			if err := tc.b.CreateGlobalKmsKeys(ctx); err != nil {
				t.Fatal(err)
			}
			if !opts.DisableInitialLoginRoleCreation {
				if _, err := tc.b.CreateInitialLoginRole(ctx); err != nil {
					t.Fatal(err)
				}
				if !opts.DisableAuthMethodCreation {
					if _, _, err := tc.b.CreateInitialPasswordAuthMethod(ctx); err != nil {
						t.Fatal(err)
					}
					if !opts.DisableOidcAuthMethodCreation {
						if err := tc.b.CreateDevOidcAuthMethod(ctx); err != nil {
							t.Fatal(err)
						}
					}
					if !opts.DisableScopesCreation {
						if _, _, err := tc.b.CreateInitialScopes(ctx); err != nil {
							t.Fatal(err)
						}
						if !opts.DisableHostResourcesCreation {
							if _, _, _, err := tc.b.CreateInitialHostResources(ctx); err != nil {
								t.Fatal(err)
							}
							if !opts.DisableTargetCreation {
								if _, err := tc.b.CreateInitialTarget(ctx); err != nil {
									t.Fatal(err)
								}
							}
						}
					}
				}
			}
		}
	} else if !opts.DisableDatabaseCreation {
		var createOpts []base.Option
		if opts.DisableAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipAuthMethodCreation())
		}
		if opts.DisableOidcAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipOidcAuthMethodCreation())
		}
		if !opts.DisableDatabaseTemplate {
			createOpts = append(createOpts, base.WithDatabaseTemplate("boundary_template"))
		}
		if err := tc.b.CreateDevDatabase(ctx, createOpts...); err != nil {
			t.Fatal(err)
		}
	}

	return &Config{
		RawConfig:                    opts.Config,
		Server:                       tc.b,
		DisableAuthorizationFailures: opts.DisableAuthorizationFailures,
	}
}

func (tc *TestController) AddClusterControllerMember(t *testing.T, opts *TestControllerOpts) *TestController {
	const op = "controller.(TestController).AddClusterControllerMember"
	if opts == nil {
		opts = new(TestControllerOpts)
	}
	nextOpts := &TestControllerOpts{
		DatabaseUrl:                 tc.c.conf.DatabaseUrl,
		DefaultPasswordAuthMethodId: tc.c.conf.DevPasswordAuthMethodId,
		DefaultOidcAuthMethodId:     tc.c.conf.DevOidcAuthMethodId,
		RootKms:                     tc.c.conf.RootKms,
		WorkerAuthKms:               tc.c.conf.WorkerAuthKms,
		RecoveryKms:                 tc.c.conf.RecoveryKms,
		Name:                        opts.Name,
		Logger:                      tc.c.conf.Logger,
		DefaultLoginName:            tc.b.DevLoginName,
		DefaultPassword:             tc.b.DevPassword,
		DisableKmsKeyCreation:       true,
		DisableAuthMethodCreation:   true,
		PublicClusterAddr:           opts.PublicClusterAddr,
		StatusGracePeriodDuration:   opts.StatusGracePeriodDuration,
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
		event.WriteSysEvent(context.TODO(), op, "controller name generated", "name", nextOpts.Name)
	}
	return NewTestController(t, nextOpts)
}

// WaitForNextWorkerStatusUpdate waits for the next status check from a worker to
// come in. If it does not come in within the default status grace
// period, this function returns an error.
func (tc *TestController) WaitForNextWorkerStatusUpdate(workerId string) error {
	const op = "controller.(TestController).WaitForNextWorkerStatusUpdate"
	ctx := context.TODO()
	event.WriteSysEvent(ctx, op, "waiting for next status report from worker", "worker", workerId)
	waitStatusStart := time.Now()
	ctx, cancel := context.WithTimeout(tc.ctx, tc.b.StatusGracePeriodDuration)
	defer cancel()
	var err error
	for {
		if err = func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()

			case <-time.After(time.Second):
				// pass
			}

			return nil
		}(); err != nil {
			break
		}

		var waitStatusCurrent time.Time
		tc.Controller().WorkerStatusUpdateTimes().Range(func(k, v interface{}) bool {
			if k == nil || v == nil {
				err = fmt.Errorf("nil key or value on entry: key=%#v value=%#v", k, v)
				return false
			}

			workerStatusUpdateId, ok := k.(string)
			if !ok {
				err = fmt.Errorf("unexpected type %T for key: key=%#v value=%#v", k, k, v)
				return false
			}

			workerStatusUpdateTime, ok := v.(time.Time)
			if !ok {
				err = fmt.Errorf("unexpected type %T for value: key=%#v value=%#v", k, k, v)
				return false
			}

			if workerStatusUpdateId == workerId {
				waitStatusCurrent = workerStatusUpdateTime
				return false
			}

			return true
		})

		if err != nil {
			break
		}

		if waitStatusCurrent.Sub(waitStatusStart) > 0 {
			break
		}
	}

	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error waiting for next status report from worker", "worker", workerId))
		return err
	}
	event.WriteSysEvent(ctx, op, "waiting for next status report from worker received successfully", "worker", workerId)
	return nil
}

// startTestGreeterService is intended to facilitate the testing of
// interceptors.  You provide a greeter service that produces appropriate
// responses to test your interceptor(s).  This test function will start up a
// test greeter service wrapped with the  specified interceptors and return an
// initialized client for the service. The test service will be stopped/cleaned
// up after the test (or subtests) have completed.
func startTestGreeterService(t *testing.T, greeter interceptor.GreeterServiceServer, interceptors ...grpc.UnaryServerInterceptor) interceptor.GreeterServiceClient {
	t.Helper()
	require := require.New(t)
	dialCtx := context.Background()

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(interceptors...)),
	)
	interceptor.RegisterGreeterServiceServer(s, greeter)
	go func() {
		err := s.Serve(listener)
		require.NoError(err)
	}()

	conn, _ := grpc.DialContext(dialCtx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithInsecure())

	t.Cleanup(func() {
		listener.Close()
		s.Stop()
	})

	client := interceptor.NewGreeterServiceClient(conn)
	return client
}
