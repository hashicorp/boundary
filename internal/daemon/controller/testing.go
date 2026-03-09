// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/gen/testing/interceptor"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const (
	DefaultOrgId                             = "o_1234567890"
	DefaultProjectId                         = "p_1234567890"
	DefaultTestPasswordAuthMethodId          = "ampw_1234567890"
	DefaultTestOidcAuthMethodId              = "amoidc_1234567890"
	DefaultTestLdapAuthMethodId              = globals.LdapAuthMethodPrefix + "_1234567890"
	DefaultTestLoginName                     = "admin"
	DefaultTestUnprivilegedLoginName         = "user"
	DefaultTestPassword                      = "passpass"
	DefaultTestUserId                        = "u_1234567890"
	DefaultTestPasswordAccountId             = globals.PasswordAccountPrefix + "_1234567890"
	DefaultTestOidcAccountId                 = "acctoidc_1234567890"
	DefaultTestUnprivilegedPasswordAccountId = globals.PasswordAccountPrefix + "_0987654321"
	DefaultTestUnprivilegedOidcAccountId     = "acctoidc_0987654321"
	DefaultTestPluginId                      = "pl_1234567890"
)

// TestController wraps a base.Server and Controller to provide a
// fully-programmatic controller for tests. Error checking (for instance, for
// valid config) is not stringent at the moment.
type TestController struct {
	b              *base.Server
	c              *Controller
	t              testing.TB
	apiAddrs       []string // The address the Controller API is listening on
	clusterAddrs   []string
	client         *api.Client
	ctx            context.Context
	cancel         context.CancelFunc
	name           string
	opts           *TestControllerOpts
	shutdownDoneCh chan struct{}
	shutdownOnce   *sync.Once
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

func (tc *TestController) ServersRepo() *server.Repository {
	repo, err := tc.c.ServersRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) ConnectionsRepo() *session.ConnectionRepository {
	repo, err := tc.c.ConnectionRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) PluginHostRepo() *plugin.Repository {
	repo, err := tc.c.PluginHostRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) VaultCredentialRepo() *vault.Repository {
	repo, err := tc.c.VaultCredentialRepoFn()
	if err != nil {
		tc.t.Fatal(err)
	}
	return repo
}

func (tc *TestController) Scheduler() *scheduler.Scheduler {
	return tc.Controller().scheduler
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
		tc.t.Fatal("no default auth method ID configured")
		return nil
	}
	result, err := authmethods.NewClient(tc.Client()).Authenticate(
		tc.Context(),
		tc.b.DevPasswordAuthMethodId,
		"login",
		map[string]any{
			"login_name": tc.b.DevLoginName,
			"password":   tc.b.DevPassword,
		},
	)
	if err != nil {
		tc.t.Fatal(fmt.Errorf("error logging in: %w", err))
		return nil
	}
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
		tc.t.Fatal(fmt.Errorf("error unmarshaling token: %w", err))
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
		map[string]any{
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
			var addr net.Addr
			switch purpose {
			case "api":
				addr = listener.ApiListener.Addr()
			case "cluster":
				addr = listener.ClusterListener.Addr()
			case "ops":
				addr = listener.OpsListener.Addr()
			}
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
	tc.shutdownOnce.Do(func() {
		if tc.b != nil {
			tc.b.ContextCancel()
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

		close(tc.shutdownDoneCh)
	})
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

	// DefaultLdapAuthMethodId is the default LDAP method ID to use, if set.
	DefaultLdapAuthMethodId string

	// DefaultLoginName is the login name used when creating the default admin account.
	DefaultLoginName string

	// DefaultUnprivilegedLoginName is the login name used when creating the default unprivileged account.
	DefaultUnprivilegedLoginName string

	// DefaultPassword is the password used when creating the default accounts.
	DefaultPassword string

	// DisableInitialLoginRoleCreation can be set true to disable creating the global
	// scope default role automatically.
	DisableInitialLoginRoleCreation bool

	// DisableAuthMethodCreation can be set true to disable creating an auth
	// method automatically.
	DisableAuthMethodCreation bool

	// DisableOidcAuthMethodCreation can be set true to disable the built-in
	// OIDC listener. Useful for e.g. unix listener tests.
	DisableOidcAuthMethodCreation bool

	// DisableLdapAuthMethodCreation can be set true to disable the built-in
	// ldap listener. Useful for e.g. unix listener tests.
	DisableLdapAuthMethodCreation bool

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

	// EnableEventing, if true the test controller will create sys and error
	// events. You must not run the test in parallel (no calls to t.Parallel)
	// since the this option relies on modifying the system wide default
	// eventer.
	EnableEventing bool

	// EventerConfig allows specifying a custom event config. You must not run
	// the test in parallel (no calls to t.Parallel) since the this option
	// relies on modifying the system wide default eventer.
	EventerConfig *event.EventerConfig

	// DisableAuthorizationFailures will still cause authz checks to be
	// performed but they won't cause 403 Forbidden. Useful for API-level
	// testing to avoid a lot of faff.
	DisableAuthorizationFailures bool

	// The controller KMS to use, or one will be created
	RootKms wrapping.Wrapper

	// The worker auth KMS to use, or one will be created
	WorkerAuthKms wrapping.Wrapper

	// The downstream worker auth KMS to use, or one will be created
	DownstreamWorkerAuthKms *multi.PooledWrapper

	// The BSR wrapper to use, or one will be created
	BsrKms wrapping.Wrapper

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

	// The registerer to use for registering all the collectors.  Nil means
	// no metrics are registered.
	PrometheusRegisterer prometheus.Registerer

	// A cluster address for overriding the advertised controller listener
	// (overrides address provided in config, if any)
	PublicClusterAddr string

	// The amount of time to wait before marking connections as canceling when a
	// worker has not reported in, and whether a worker is considered to be
	// routable based on the last time it received a routing info report.
	WorkerRPCGracePeriod time.Duration

	// The period of time after which it will consider other controllers to be
	// no longer accessible, based on time since their last status update in the
	// database
	LivenessTimeToStaleDuration time.Duration

	// The amount of time between the scheduler waking up to run it's
	// registered jobs.
	//
	// If t.Deadline() has a value and the value is under 1 minute, the
	// default value is set to half the value of t.Deadline(). If
	// t.Deadline() has a value and the value is 1 minute or more, the
	// default value is set to 1 minute.
	//
	// Tests using the Vault test server should be aware that Vault
	// Credential Stores only accept Vault tokens that have a TTL greater
	// than the SchedulerRunJobInterval. The Vault test server, by default,
	// creates Vault tokens with a TTL equal to the duration of time
	// remaining until t.Deadline() is reached.
	SchedulerRunJobInterval time.Duration

	// The time to use for CA certificate lifetime for worker auth
	WorkerAuthCaCertificateLifetime time.Duration

	// Toggle worker auth debugging
	WorkerAuthDebuggingEnabled *atomic.Bool

	DisableRateLimiting bool

	EnableIPv6 bool
}

func NewTestController(t testing.TB, opts *TestControllerOpts) *TestController {
	const op = "controller.NewTestController"
	ctx, cancel := context.WithCancel(context.Background())

	if opts == nil {
		opts = new(TestControllerOpts)
	}

	tc := &TestController{
		t:              t,
		ctx:            ctx,
		cancel:         cancel,
		opts:           opts,
		shutdownDoneCh: make(chan struct{}),
		shutdownOnce:   new(sync.Once),
	}
	t.Cleanup(tc.Shutdown)

	conf := TestControllerConfig(t, ctx, tc, opts)
	var err error
	tc.c, err = New(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}

	tc.buildClient()

	// The real server functions will listen for shutdown cues and act so mimic
	// that here, and ensure that channels get drained
	go func() {
		for {
			select {
			case <-tc.b.ShutdownCh:
				tc.Shutdown()
			case <-tc.b.ServerSideShutdownCh:
				tc.Shutdown()
			case <-tc.shutdownDoneCh:
				return
			}
		}
	}()

	if !opts.DisableAutoStart {
		if err := tc.c.Start(); err != nil {
			t.Fatal(err)
		}
	}

	return tc
}

// TestControllerConfig provides a way to create a config for a TestController.
// The tc passed as a parameter will be modified by this func.
func TestControllerConfig(t testing.TB, ctx context.Context, tc *TestController, opts *TestControllerOpts) *Config {
	const op = "controller.TestControllerConfig"
	if opts == nil {
		opts = new(TestControllerOpts)
	}

	ctxTest, cancel := context.WithCancel(context.Background())

	// Base server
	tc.b = base.NewServer(&base.Command{
		Context:       ctxTest,
		ContextCancel: cancel,
		ShutdownCh:    make(chan struct{}),
	})
	tc.b.WorkerAuthDebuggingEnabled = opts.WorkerAuthDebuggingEnabled

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
		cfgOpts := append([]config.Option{}, config.WithIPv6Enabled(true))
		opts.Config, err = config.DevController(cfgOpts...)
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
	if opts.DefaultLdapAuthMethodId != "" {
		tc.b.DevLdapAuthMethodId = opts.DefaultLdapAuthMethodId
	} else {
		tc.b.DevLdapAuthMethodId = DefaultTestLdapAuthMethodId
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
	tc.b.DevLoopbackPluginId = DefaultTestPluginId

	// Alias targets are only used as a dev example
	tc.b.SkipAliasTargetCreation = true

	tc.b.EnabledPlugins = append(tc.b.EnabledPlugins, base.EnabledPluginLoopback)

	// Start a logger
	tc.b.Logger = opts.Logger
	if tc.b.Logger == nil {
		tc.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
			Mutex: tc.b.StderrLock,
		})
	}

	tc.b.PrometheusRegisterer = opts.PrometheusRegisterer
	if opts.Config.Controller == nil {
		opts.Config.Controller = new(config.Controller)
	}
	if opts.Config.Controller.Name == "" {
		require.NoError(t, opts.Config.Controller.InitNameIfEmpty(ctxTest))
	}

	if opts.SchedulerRunJobInterval == 0 {
		if t, ok := t.(*testing.T); ok {
			if deadline, ok := t.Deadline(); ok {
				opts.SchedulerRunJobInterval = 1 * time.Minute
				if time.Until(deadline) < opts.SchedulerRunJobInterval {
					half := int64(time.Until(deadline) / 2)
					opts.SchedulerRunJobInterval = time.Duration(half)
				}
			}
		}
	}
	opts.Config.Controller.Scheduler.JobRunIntervalDuration = opts.SchedulerRunJobInterval
	opts.Config.Controller.ApiRateLimiterMaxQuotas = ratelimit.DefaultLimiterMaxQuotas()

	if opts.EnableEventing || opts.EventerConfig != nil {
		opts.Config.Eventing = opts.EventerConfig
		if opts.Config.Eventing == nil {
			opts.Config.Eventing = &event.EventerConfig{
				AuditEnabled:        true,
				ObservationsEnabled: true,
				SysEventsEnabled:    true,
				ErrorEventsDisabled: true,
			}
		}
	}
	serverName, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	serverName = fmt.Sprintf("%s/controller", serverName)
	if err := tc.b.SetupEventing(ctxTest, tc.b.Logger, tc.b.StderrLock, serverName, base.WithEventerConfig(opts.Config.Eventing)); err != nil {
		t.Fatal(err)
	}

	if opts.WorkerRPCGracePeriod != 0 {
		opts.Config.Controller.WorkerRPCGracePeriodDuration = opts.WorkerRPCGracePeriod
	}
	if opts.LivenessTimeToStaleDuration != 0 {
		opts.Config.Controller.LivenessTimeToStaleDuration = opts.LivenessTimeToStaleDuration
	}

	tc.name = opts.Config.Controller.Name

	if opts.InitialResourcesSuffix != "" {
		suffix := opts.InitialResourcesSuffix
		tc.b.DevPasswordAuthMethodId = "ampw_" + suffix
		tc.b.DevOidcAuthMethodId = "amoidc_" + suffix
		tc.b.DevLdapAuthMethodId = globals.LdapAuthMethodPrefix + "_" + suffix
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
	if err := tc.b.SetupKMSes(tc.b.Context, nil, opts.Config); err != nil {
		t.Fatal(err)
	}
	if opts.RootKms != nil {
		tc.b.RootKms = opts.RootKms
	}
	if opts.WorkerAuthKms != nil {
		tc.b.WorkerAuthKms = opts.WorkerAuthKms
	}
	if opts.DownstreamWorkerAuthKms != nil {
		tc.b.DownstreamWorkerAuthKms = opts.DownstreamWorkerAuthKms
	}
	if opts.BsrKms != nil {
		tc.b.BsrKms = opts.BsrKms
	}
	if opts.RecoveryKms != nil {
		tc.b.RecoveryKms = opts.RecoveryKms
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tc.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"api", "cluster", "ops"}); err != nil {
		t.Fatal(err)
	}
	if err := opts.Config.SetupControllerPublicClusterAddress(""); err != nil {
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
		if err := tc.b.OpenAndSetServerDatabase(tc.ctx, "postgres"); err != nil {
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
				if _, err := tc.b.CreateInitialAuthenticatedUserRole(ctx); err != nil {
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
					if !opts.DisableLdapAuthMethodCreation {
						if err := tc.b.CreateDevLdapAuthMethod(ctx); err != nil {
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
								if _, err := tc.b.CreateInitialTargetWithHostSources(ctx); err != nil {
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
		if opts.DisableInitialLoginRoleCreation {
			createOpts = append(createOpts, base.WithSkipDefaultRoleCreation())
		}
		if opts.DisableAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipAuthMethodCreation())
		}
		if opts.DisableOidcAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipOidcAuthMethodCreation())
		}
		if opts.DisableOidcAuthMethodCreation {
			createOpts = append(createOpts, base.WithSkipLdapAuthMethodCreation())
		}
		if !opts.DisableDatabaseTemplate {
			createOpts = append(createOpts, base.WithDatabaseTemplate("boundary_template"))
		}
		if err := tc.b.CreateDevDatabase(ctx, createOpts...); err != nil {
			t.Fatal(err)
		}
	}

	if opts.DisableRateLimiting {
		opts.Config.Controller.ApiRateLimitDisable = true
	}

	return &Config{
		RawConfig:                    opts.Config,
		Server:                       tc.b,
		DisableAuthorizationFailures: opts.DisableAuthorizationFailures,
		TestOverrideWorkerAuthCaCertificateLifetime: opts.WorkerAuthCaCertificateLifetime,
	}
}

func (tc *TestController) AddClusterControllerMember(t testing.TB, opts *TestControllerOpts) *TestController {
	const op = "controller.(TestController).AddClusterControllerMember"
	if opts == nil {
		opts = new(TestControllerOpts)
	}
	nextOpts := &TestControllerOpts{
		DatabaseUrl:                     tc.c.conf.DatabaseUrl,
		DefaultPasswordAuthMethodId:     tc.c.conf.DevPasswordAuthMethodId,
		DefaultOidcAuthMethodId:         tc.c.conf.DevOidcAuthMethodId,
		DefaultLdapAuthMethodId:         tc.c.conf.DevLdapAuthMethodId,
		RootKms:                         tc.c.conf.RootKms,
		WorkerAuthKms:                   tc.c.conf.WorkerAuthKms,
		DownstreamWorkerAuthKms:         tc.c.conf.DownstreamWorkerAuthKms,
		BsrKms:                          tc.c.conf.BsrKms,
		RecoveryKms:                     tc.c.conf.RecoveryKms,
		Name:                            opts.Name,
		Logger:                          tc.c.conf.Logger,
		DefaultLoginName:                tc.b.DevLoginName,
		DefaultPassword:                 tc.b.DevPassword,
		DisableKmsKeyCreation:           true,
		DisableAuthMethodCreation:       true,
		DisableAutoStart:                opts.DisableAutoStart,
		PublicClusterAddr:               opts.PublicClusterAddr,
		WorkerRPCGracePeriod:            opts.WorkerRPCGracePeriod,
		LivenessTimeToStaleDuration:     opts.LivenessTimeToStaleDuration,
		WorkerAuthCaCertificateLifetime: tc.c.conf.TestOverrideWorkerAuthCaCertificateLifetime,
		WorkerAuthDebuggingEnabled:      tc.c.conf.WorkerAuthDebuggingEnabled,
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

// WaitForNextWorkerRoutingInfoUpdate waits for the next routing info RPC from a worker to
// come in. If it does not come in within the default worker RPC grace
// period, this function returns an error.
func (tc *TestController) WaitForNextWorkerRoutingInfoUpdate(workerName string) error {
	const op = "controller.(TestController).WaitForNextWorkerRoutingInfoUpdate"
	waitStart := time.Now()
	ctx, cancel := context.WithTimeout(tc.ctx, time.Duration(tc.c.workerRPCGracePeriod.Load()))
	defer cancel()
	event.WriteSysEvent(ctx, op, "waiting for next routing info from worker", "worker", workerName)
	var err error
	for {
		select {
		case <-ctx.Done():
			break
		case <-time.After(time.Second):
			// pass
		}

		var waitCurrent time.Time
		tc.Controller().WorkerRoutingInfoUpdateTimes().Range(func(k, v any) bool {
			if k == nil || v == nil {
				err = fmt.Errorf("nil key or value on entry: key=%#v value=%#v", k, v)
				return false
			}

			workerUpdateId, ok := k.(string)
			if !ok {
				err = fmt.Errorf("unexpected type %T for key: key=%#v value=%#v", k, k, v)
				return false
			}

			workerUpdateTime, ok := v.(time.Time)
			if !ok {
				err = fmt.Errorf("unexpected type %T for value: key=%#v value=%#v", k, k, v)
				return false
			}

			if workerUpdateId == workerName {
				waitCurrent = workerUpdateTime
				return false
			}

			return true
		})

		if err != nil {
			break
		}

		if waitCurrent.After(waitStart) {
			break
		}
	}

	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error waiting for next routing info RPC from worker", "worker", workerName))
		return err
	}
	event.WriteSysEvent(ctx, op, "next routing info RPC from worker received successfully", "worker", workerName)
	return nil
}

// startTestGreeterService is intended to facilitate the testing of
// interceptors.  You provide a greeter service that produces appropriate
// responses to test your interceptor(s).  This test function will start up a
// test greeter service wrapped with the  specified interceptors and return an
// initialized client for the service. The test service will be stopped/cleaned
// up after the test (or subtests) have completed.
func startTestGreeterService(t testing.TB, greeter interceptor.GreeterServiceServer, interceptors ...grpc.UnaryServerInterceptor) interceptor.GreeterServiceClient {
	t.Helper()
	require := require.New(t)
	dialCtx := context.Background()

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(interceptors...)),
	)
	interceptor.RegisterGreeterServiceServer(s, greeter)
	// Use error channel so that we can use test assertions on the returned error.
	// It is illegal to call `t.FailNow()` from a goroutine.
	// https://pkg.go.dev/testing#T.FailNow
	errChan := make(chan error)
	go func() {
		errChan <- s.Serve(listener)
	}()
	t.Cleanup(func() {
		// Will block until we stopped serving
		require.NoError(<-errChan)
	})

	conn, _ := grpc.DialContext(dialCtx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))

	t.Cleanup(func() {
		listener.Close()
		s.Stop()
	})

	client := interceptor.NewGreeterServiceClient(conn)
	return client
}
