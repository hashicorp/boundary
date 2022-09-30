package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/health"
	"github.com/hashicorp/boundary/internal/daemon/controller/internal/metric"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	kmsjob "github.com/hashicorp/boundary/internal/kms/job"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/plugin/host"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/server"
	serversjob "github.com/hashicorp/boundary/internal/server/job"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	host_plugin_assets "github.com/hashicorp/boundary/plugins/host"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	external_host_plugins "github.com/hashicorp/boundary/sdk/plugins/host"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc"
)

// downstreamRouter defines a min interface which must be met by a
// Controller.downstreamRoutes field
type downstreamRouter interface {
	// StartRouteMgmtTicking starts a ticker which manages the router's
	// connections.
	StartRouteMgmtTicking(context.Context, func() string, int) error
}

// downstreamWorkersTicker defines an interface for a ticker that maintains the
// graph of the controller's downstream workers
type downstreamWorkersTicker interface {
	// StartDownstreamWorkersTicking is used by a Controller to maintain their
	// graph of downstream workers.
	StartDownstreamWorkersTicking(context.Context, int) error
}

// downstreamers provides at least a minimum interface that must be met by a
// Controller.downstreamWorkers field which is far better than allowing any (empty
// interface)
type downstreamers interface {
	// Root returns the root of the downstreamers' graph
	Root() string
}

var (
	downstreamRouterFactory func() downstreamRouter

	downstreamersFactory           func(context.Context, string) (downstreamers, error)
	downstreamWorkersTickerFactory func(context.Context, string, downstreamers, downstreamRouter) (downstreamWorkersTicker, error)
	commandClientFactory           func(context.Context, *Controller) error
)

type Controller struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg    *sync.WaitGroup
	schedulerWg *sync.WaitGroup

	workerAuthCache *sync.Map

	// downstream workers and routes to those workers
	downstreamWorkers downstreamers
	downstreamRoutes  downstreamRouter

	apiListeners    []*base.ServerListener
	clusterListener *base.ServerListener

	// Used for testing and tracking worker health
	workerStatusUpdateTimes *sync.Map

	apiGrpcServer         *grpc.Server
	apiGrpcServerListener grpcServerListener
	apiGrpcGatewayTicket  string

	// Repo factory methods
	AuthTokenRepoFn         common.AuthTokenRepoFactory
	VaultCredentialRepoFn   common.VaultCredentialRepoFactory
	StaticCredentialRepoFn  common.StaticCredentialRepoFactory
	IamRepoFn               common.IamRepoFactory
	OidcRepoFn              common.OidcAuthRepoFactory
	PasswordAuthRepoFn      common.PasswordAuthRepoFactory
	ServersRepoFn           common.ServersRepoFactory
	SessionRepoFn           session.RepositoryFactory
	ConnectionRepoFn        common.ConnectionRepoFactory
	StaticHostRepoFn        common.StaticRepoFactory
	PluginHostRepoFn        common.PluginHostRepoFactory
	HostPluginRepoFn        common.HostPluginRepoFactory
	TargetRepoFn            target.RepositoryFactory
	WorkerAuthRepoStorageFn common.WorkerAuthRepoStorageFactory

	scheduler *scheduler.Scheduler

	kms *kms.Kms

	enabledPlugins []base.EnabledPlugin

	// Used to signal the Health Service to start
	// replying to queries with "503 Service Unavailable".
	HealthService *health.Service
}

func New(ctx context.Context, conf *Config) (*Controller, error) {
	metric.InitializeApiCollectors(conf.PrometheusRegisterer)
	c := &Controller{
		conf:                    conf,
		logger:                  conf.Logger.Named("controller"),
		started:                 ua.NewBool(false),
		tickerWg:                new(sync.WaitGroup),
		schedulerWg:             new(sync.WaitGroup),
		workerAuthCache:         new(sync.Map),
		workerStatusUpdateTimes: new(sync.Map),
		enabledPlugins:          conf.Server.EnabledPlugins,
		apiListeners:            make([]*base.ServerListener, 0),
	}

	if downstreamRouterFactory != nil {
		c.downstreamRoutes = downstreamRouterFactory()
	}

	c.started.Store(false)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Controller == nil {
		conf.RawConfig.Controller = new(config.Controller)
	}

	if err := conf.RawConfig.Controller.InitNameIfEmpty(); err != nil {
		return nil, fmt.Errorf("error auto-generating controller name: %w", err)
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

	clusterListeners := make([]*base.ServerListener, 0)
	for i := range conf.Listeners {
		l := conf.Listeners[i]
		if l == nil || l.Config == nil || l.Config.Purpose == nil {
			continue
		}
		if len(l.Config.Purpose) != 1 {
			return nil, fmt.Errorf("found listener with multiple purposes %q", strings.Join(l.Config.Purpose, ","))
		}
		switch l.Config.Purpose[0] {
		case "api":
			c.apiListeners = append(c.apiListeners, l)
		case "cluster":
			clusterListeners = append(clusterListeners, l)
		}
	}
	if len(c.apiListeners) == 0 {
		return nil, fmt.Errorf("no api listeners found")
	}
	if len(clusterListeners) != 1 {
		// in the future, we might pick the cluster that is exposed to the outside
		// instead of limiting it to one.
		return nil, fmt.Errorf("exactly one cluster listener is required")
	}
	c.clusterListener = clusterListeners[0]

	var pluginLogger hclog.Logger
	for _, enabledPlugin := range c.enabledPlugins {
		if pluginLogger == nil {
			pluginLogger, err = event.NewHclogLogger(ctx, c.conf.Server.Eventer)
			if err != nil {
				return nil, fmt.Errorf("error creating host catalog plugin logger: %w", err)
			}
		}
		switch enabledPlugin {
		case base.EnabledPluginHostLoopback:
			plg := pluginhost.NewWrappingPluginClient(pluginhost.NewLoopbackPlugin())
			opts := []hostplugin.Option{
				hostplugin.WithDescription("Provides an initial loopback host plugin in Boundary"),
				hostplugin.WithPublicId(conf.DevLoopbackHostPluginId),
			}
			if _, err = conf.RegisterHostPlugin(ctx, "loopback", plg, opts...); err != nil {
				return nil, err
			}
		case base.EnabledPluginHostAzure, base.EnabledPluginHostAws:
			pluginType := strings.ToLower(enabledPlugin.String())
			client, cleanup, err := external_host_plugins.CreateHostPlugin(
				ctx,
				pluginType,
				external_host_plugins.WithPluginOptions(
					pluginutil.WithPluginExecutionDirectory(conf.RawConfig.Plugins.ExecutionDir),
					pluginutil.WithPluginsFilesystem(host_plugin_assets.HostPluginPrefix, host_plugin_assets.FileSystem()),
				),
				external_host_plugins.WithLogger(pluginLogger.Named(pluginType)),
			)
			if err != nil {
				return nil, fmt.Errorf("error creating %s host plugin: %w", pluginType, err)
			}
			conf.ShutdownFuncs = append(conf.ShutdownFuncs, cleanup)
			if _, err := conf.RegisterHostPlugin(ctx, pluginType, client, hostplugin.WithDescription(fmt.Sprintf("Built-in %s host plugin", enabledPlugin.String()))); err != nil {
				return nil, fmt.Errorf("error registering %s host plugin: %w", pluginType, err)
			}
		}
	}

	if conf.HostPlugins == nil {
		conf.HostPlugins = make(map[string]plugin.HostPluginServiceClient)
	}

	// Set up repo stuff
	dbase := db.New(c.conf.Database)
	c.kms, err = kms.New(ctx, dbase, dbase)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := c.kms.AddExternalWrappers(
		ctx,
		kms.WithRootWrapper(c.conf.RootKms),
		kms.WithWorkerAuthWrapper(c.conf.WorkerAuthKms),
		kms.WithRecoveryWrapper(c.conf.RecoveryKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	// we need to get all the scopes so we can reconcile the DEKs for each scope.
	iamRepo, err := iam.NewRepository(dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iam repository: %w", err)
	}
	allScopes, err := iamRepo.ListScopesRecursively(ctx, scope.Global.String())
	if err != nil {
		return nil, fmt.Errorf("error listing all scopes for reconciling keys: %w", err)
	}
	reconcileScopeIds := make([]string, 0, len(allScopes))
	for _, s := range allScopes {
		reconcileScopeIds = append(reconcileScopeIds, s.PublicId)
	}
	if err := c.kms.ReconcileKeys(ctx, c.conf.SecureRandomReader, kms.WithScopeIds(reconcileScopeIds...)); err != nil {
		return nil, fmt.Errorf("error reconciling kms keys: %w", err)
	}

	// now that the kms is configured, we can get the audit wrapper and rotate
	// the eventer audit wrapper, so the emitted events can include encrypt and
	// hmac-sha256 data
	auditWrapper, err := c.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeAudit)
	if err != nil {
		return nil, fmt.Errorf("error getting audit wrapper from kms: %w", err)
	}
	if err := c.conf.Eventer.RotateAuditWrapper(ctx, auditWrapper); err != nil {
		return nil, fmt.Errorf("error rotating eventer audit wrapper: %w", err)
	}
	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(dbase, dbase, c.kms)
	}
	// TODO: Allow setting run jobs limit from config
	schedulerOpts := []scheduler.Option{scheduler.WithRunJobsLimit(-1)}
	if sche := c.conf.RawConfig.Controller.Scheduler; sche != nil {
		if sche.JobRunIntervalDuration > 0 {
			schedulerOpts = append(schedulerOpts, scheduler.WithRunJobsInterval(sche.JobRunIntervalDuration))
		}
		if sche.MonitorIntervalDuration > 0 {
			schedulerOpts = append(schedulerOpts, scheduler.WithMonitorInterval(sche.MonitorIntervalDuration))
		}
	}
	c.scheduler, err = scheduler.New(c.conf.RawConfig.Controller.Name, jobRepoFn, schedulerOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating new scheduler: %w", err)
	}
	c.IamRepoFn = func() (*iam.Repository, error) {
		return iam.NewRepository(dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.StaticHostRepoFn = func() (*static.Repository, error) {
		return static.NewRepository(dbase, dbase, c.kms)
	}
	c.PluginHostRepoFn = func() (*pluginhost.Repository, error) {
		return pluginhost.NewRepository(dbase, dbase, c.kms, c.scheduler, c.conf.HostPlugins)
	}
	c.HostPluginRepoFn = func() (*host.Repository, error) {
		return host.NewRepository(dbase, dbase, c.kms)
	}
	c.AuthTokenRepoFn = func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(dbase, dbase, c.kms,
			authtoken.WithTokenTimeToLiveDuration(c.conf.RawConfig.Controller.AuthTokenTimeToLiveDuration),
			authtoken.WithTokenTimeToStaleDuration(c.conf.RawConfig.Controller.AuthTokenTimeToStaleDuration))
	}
	c.VaultCredentialRepoFn = func() (*vault.Repository, error) {
		return vault.NewRepository(dbase, dbase, c.kms, c.scheduler)
	}
	c.StaticCredentialRepoFn = func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.ServersRepoFn = func() (*server.Repository, error) {
		return server.NewRepository(dbase, dbase, c.kms)
	}
	c.OidcRepoFn = func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(dbase, dbase, c.kms)
	}
	c.TargetRepoFn = func(o ...target.Option) (*target.Repository, error) {
		return target.NewRepository(ctx, dbase, dbase, c.kms, o...)
	}
	c.SessionRepoFn = func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, dbase, dbase, c.kms, opt...)
	}
	c.ConnectionRepoFn = func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, dbase, dbase, c.kms)
	}
	c.WorkerAuthRepoStorageFn = func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, dbase, dbase, c.kms)
	}

	// Check that credentials are available at startup, to avoid some harmless
	// but nasty-looking errors
	serversRepo, err := server.NewRepositoryStorage(ctx, dbase, dbase, c.kms)
	if err != nil {
		return nil, fmt.Errorf("unable to instantiate worker auth repository: %w", err)
	}
	_, err = server.RotateRoots(ctx, serversRepo)
	if err != nil {
		return nil, fmt.Errorf("unable to ensure worker auth roots exist: %w", err)
	}

	if downstreamersFactory != nil {
		c.downstreamWorkers, err = downstreamersFactory(ctx, "root")
		if err != nil {
			return nil, fmt.Errorf("unable to initialize downstream workers graph: %w", err)
		}
		if commandClientFactory != nil {
			err := commandClientFactory(ctx, c)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize issue command factory: %w", err)
			}
		}
	}

	return c, nil
}

func (c *Controller) Start() error {
	const op = "controller.(Controller).Start"
	if c.started.Load() {
		event.WriteSysEvent(context.TODO(), op, "already started, skipping")
		return nil
	}

	c.baseContext, c.baseCancel = context.WithCancel(context.Background())

	if err := c.registerJobs(); err != nil {
		return fmt.Errorf("error registering jobs: %w", err)
	}
	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting controller listeners: %w", err)
	}

	// Upsert controller before starting tickers and scheduler to ensure the controller exists
	if err := c.upsertController(c.baseContext); err != nil {
		return fmt.Errorf("error upserting controller: %w", err)
	}
	if err := c.scheduler.Start(c.baseContext, c.schedulerWg); err != nil {
		return fmt.Errorf("error starting scheduler: %w", err)
	}

	c.tickerWg.Add(5)
	go func() {
		defer c.tickerWg.Done()
		c.startStatusTicking(c.baseContext)
	}()
	go func() {
		defer c.tickerWg.Done()
		c.startNonceCleanupTicking(c.baseContext)
	}()
	go func() {
		defer c.tickerWg.Done()
		c.startTerminateCompletedSessionsTicking(c.baseContext)
	}()
	go func() {
		defer c.tickerWg.Done()
		c.startCloseExpiredPendingTokens(c.baseContext)
	}()
	go func() {
		defer c.tickerWg.Done()
		c.started.Store(true)
	}()

	if c.downstreamRoutes != nil {
		c.tickerWg.Add(1)
		go func() {
			defer c.tickerWg.Done()
			err := c.downstreamRoutes.StartRouteMgmtTicking(
				c.baseContext,
				func() string {
					switch {
					case c.conf.RawConfig.Controller.Name != "":
						return c.conf.RawConfig.Controller.Name
					default:
						return "unknown controller name"
					}
				},
				-1,
			)
			if err != nil {
				errors.Wrap(c.baseContext, err, op)
			}
		}()
	}
	if downstreamWorkersTickerFactory != nil {
		// we'll use "root" to designate that this is the root of the graph (aka
		// a controller)
		dswTicker, err := downstreamWorkersTickerFactory(c.baseContext, "root", c.downstreamWorkers, c.downstreamRoutes)
		if err != nil {
			return fmt.Errorf("error creating downstream workers ticker: %w", err)
		}
		c.tickerWg.Add(1)
		go func() {
			defer c.tickerWg.Done()
			err := dswTicker.StartDownstreamWorkersTicking(c.baseContext, -1)
			if err != nil {
				event.WriteSysEvent(c.baseContext, op, "error starting/running downstream workers ticker", "err", err.Error())
			}
		}()
	}

	return nil
}

func (c *Controller) registerJobs() error {
	rw := db.New(c.conf.Database)
	if err := vault.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms); err != nil {
		return err
	}
	if err := pluginhost.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms, c.conf.HostPlugins); err != nil {
		return err
	}
	if err := session.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms, c.conf.StatusGracePeriodDuration); err != nil {
		return err
	}
	if err := serversjob.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms); err != nil {
		return err
	}
	if err := kmsjob.RegisterJobs(c.baseContext, c.scheduler, c.kms); err != nil {
		return err
	}

	return nil
}

func (c *Controller) Shutdown() error {
	const op = "controller.(Controller).Shutdown"
	if !c.started.Load() {
		event.WriteSysEvent(context.TODO(), op, "already shut down, skipping")
	}
	defer c.started.Store(false)
	c.baseCancel()
	if err := c.stopServersAndListeners(); err != nil {
		return fmt.Errorf("error stopping controller servers and listeners: %w", err)
	}
	c.schedulerWg.Wait()
	c.tickerWg.Wait()
	if c.conf.Eventer != nil {
		if err := c.conf.Eventer.FlushNodes(context.Background()); err != nil {
			return fmt.Errorf("error flushing controller eventer nodes: %w", err)
		}
	}
	return nil
}

// WorkerStatusUpdateTimes returns the map, which specifically is held in _this_
// controller, not the DB. It's used in tests to verify that a given controller
// is receiving updates from an expected set of workers, to test out balancing
// and auto reconnection.
func (c *Controller) WorkerStatusUpdateTimes() *sync.Map {
	return c.workerStatusUpdateTimes
}
