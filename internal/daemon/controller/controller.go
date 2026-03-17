// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/alias"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/billing"
	"github.com/hashicorp/boundary/internal/census"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/downstream"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/health"
	"github.com/hashicorp/boundary/internal/daemon/controller/internal/metric"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/host"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	kmsjob "github.com/hashicorp/boundary/internal/kms/job"
	"github.com/hashicorp/boundary/internal/pagination/purge"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/recording"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/server"
	serversjob "github.com/hashicorp/boundary/internal/server/job"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/snapshot"
	pluginstorage "github.com/hashicorp/boundary/internal/storage/plugin"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	boundary_plugin_assets "github.com/hashicorp/boundary/plugins/boundary"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	external_plugins "github.com/hashicorp/boundary/sdk/plugins"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/nodeenrollment"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc"
)

// downstreamReceiver defines a min interface which must be met by a
// Controller.downstreamConns field
type downstreamReceiver interface {
	// StartConnectionMgmtTicking starts a ticker which manages the receiver's
	// connections.
	StartConnectionMgmtTicking(context.Context, func() string, int) error

	// StartProcessingPendingConnections starts a function that continually processes
	// incoming client connections. This only returns when the provided context
	// is done.
	StartProcessingPendingConnections(context.Context, func() string) error
}

// downstreamWorkersTicker defines an interface for a ticker that maintains the
// graph of the controller's downstream workers
type downstreamWorkersTicker interface {
	// StartDownstreamWorkersTicking is used by a Controller to maintain their
	// graph of downstream workers.
	StartDownstreamWorkersTicking(context.Context, int) error
}

var (
	downstreamReceiverFactory func(*atomic.Int64) (downstreamReceiver, error)

	graphFactory                   func(context.Context, string, string) (downstream.Graph, error)
	downstreamWorkersTickerFactory func(context.Context, string, string, downstream.Graph, downstreamReceiver, *atomic.Int64) (downstreamWorkersTicker, error)
	commandClientFactory           func(context.Context, *Controller) error
	extControllerFactory           func(ctx context.Context, c *Controller, r db.Reader, w db.Writer, kms *kms.Kms) (intglobals.ControllerExtension, error)
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
	downstreamWorkers downstream.Graph
	downstreamConns   downstreamReceiver

	apiListeners    []*base.ServerListener
	clusterListener *base.ServerListener

	// Used for testing and tracking worker health
	workerRoutingInfoUpdateTimes *sync.Map

	// Timing variables. These are atomics for SIGHUP support, and are int64
	// because they are casted to time.Duration.
	workerRPCGracePeriod        *atomic.Int64
	livenessTimeToStale         *atomic.Int64
	getDownstreamWorkersTimeout *atomic.Int64

	apiGrpcServer         *grpc.Server
	apiGrpcServerListener grpcServerListener
	apiGrpcGatewayTicket  string

	rateLimiter   ratelimit.Limiter
	rateLimiterMu sync.RWMutex

	// Repo factory methods
	AuthTokenRepoFn           common.AuthTokenRepoFactory
	VaultCredentialRepoFn     common.VaultCredentialRepoFactory
	StaticCredentialRepoFn    common.StaticCredentialRepoFactory
	CredentialStoreRepoFn     common.CredentialStoreRepoFactory
	HostCatalogRepoFn         common.HostCatalogRepoFactory
	IamRepoFn                 common.IamRepoFactory
	OidcRepoFn                common.OidcAuthRepoFactory
	LdapRepoFn                common.LdapAuthRepoFactory
	PasswordAuthRepoFn        common.PasswordAuthRepoFactory
	AuthMethodRepoFn          common.AuthMethodRepoFactory
	ServersRepoFn             common.ServersRepoFactory
	SessionRepoFn             session.RepositoryFactory
	ConnectionRepoFn          common.ConnectionRepoFactory
	StaticHostRepoFn          common.StaticRepoFactory
	PluginHostRepoFn          common.PluginHostRepoFactory
	PluginStorageBucketRepoFn common.PluginStorageBucketRepoFactory
	PluginRepoFn              common.PluginRepoFactory
	TargetRepoFn              target.RepositoryFactory
	WorkerAuthRepoStorageFn   common.WorkerAuthRepoStorageFactory
	BillingRepoFn             common.BillingRepoFactory
	AliasRepoFn               common.AliasRepoFactory
	TargetAliasRepoFn         common.TargetAliasRepoFactory

	scheduler *scheduler.Scheduler

	kms *kms.Kms

	enabledPlugins []base.EnabledPlugin

	// Used to signal the Health Service to start
	// replying to queries with "503 Service Unavailable".
	HealthService *health.Service

	downstreamConnManager *cluster.DownstreamManager

	// ControllerExtension defines a std way to extend the controller
	ControllerExtension intglobals.ControllerExtension
}

func New(ctx context.Context, conf *Config) (*Controller, error) {
	const op = "controller.New"
	metric.InitializeApiCollectors(conf.PrometheusRegisterer)
	ratelimit.InitializeMetrics(conf.PrometheusRegisterer)
	c := &Controller{
		conf:                         conf,
		logger:                       conf.Logger.Named("controller"),
		started:                      ua.NewBool(false),
		tickerWg:                     new(sync.WaitGroup),
		schedulerWg:                  new(sync.WaitGroup),
		workerAuthCache:              new(sync.Map),
		workerRoutingInfoUpdateTimes: new(sync.Map),
		enabledPlugins:               conf.Server.EnabledPlugins,
		apiListeners:                 make([]*base.ServerListener, 0),
		downstreamConnManager:        cluster.NewDownstreamManager(),
		workerRPCGracePeriod:         new(atomic.Int64),
		livenessTimeToStale:          new(atomic.Int64),
		getDownstreamWorkersTimeout:  new(atomic.Int64),
	}

	c.started.Store(false)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Controller == nil {
		conf.RawConfig.Controller = new(config.Controller)
	}

	if err := conf.RawConfig.Controller.InitNameIfEmpty(ctx); err != nil {
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

	switch conf.RawConfig.Controller.WorkerRPCGracePeriodDuration {
	case 0:
		c.workerRPCGracePeriod.Store(int64(server.DefaultLiveness))
	default:
		c.workerRPCGracePeriod.Store(int64(conf.RawConfig.Controller.WorkerRPCGracePeriodDuration))
	}
	switch conf.RawConfig.Controller.LivenessTimeToStaleDuration {
	case 0:
		c.livenessTimeToStale.Store(int64(server.DefaultLiveness))
	default:
		c.livenessTimeToStale.Store(int64(conf.RawConfig.Controller.LivenessTimeToStaleDuration))
	}

	switch conf.RawConfig.Controller.GetDownstreamWorkersTimeoutDuration {
	case 0:
		c.getDownstreamWorkersTimeout.Store(int64(server.DefaultLiveness))
	default:
		c.getDownstreamWorkersTimeout.Store(int64(conf.RawConfig.Controller.GetDownstreamWorkersTimeoutDuration))
	}

	if downstreamReceiverFactory != nil {
		var err error
		c.downstreamConns, err = downstreamReceiverFactory(c.getDownstreamWorkersTimeout)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to initialize downstream receiver: %w", op, err)
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

	if err := c.initializeRateLimiter(conf.RawConfig); err != nil {
		return nil, fmt.Errorf("error initializing rate limiter: %w", err)
	}

	var pluginLogger hclog.Logger
	for _, enabledPlugin := range c.enabledPlugins {
		if pluginLogger == nil {
			pluginLogger, err = event.NewHclogLogger(ctx, c.conf.Server.Eventer)
			if err != nil {
				return nil, fmt.Errorf("error creating host catalog plugin logger: %w", err)
			}
		}
		switch {
		case enabledPlugin == base.EnabledPluginLoopback:
			lp, err := loopback.NewLoopbackPlugin()
			if err != nil {
				return nil, fmt.Errorf("error creating loopback plugin: %w", err)
			}
			plg := loopback.NewWrappingPluginHostClient(lp)
			opts := []plugin.Option{
				plugin.WithDescription("Provides an initial loopback storage and host plugin in Boundary"),
				plugin.WithPublicId(conf.DevLoopbackPluginId),
			}
			if _, err = conf.RegisterPlugin(ctx, "loopback", plg, []plugin.PluginType{plugin.PluginTypeHost, plugin.PluginTypeStorage}, opts...); err != nil {
				return nil, err
			}
		case enabledPlugin == base.EnabledPluginHostAzure && !c.conf.SkipPlugins:
			pluginType := strings.ToLower(enabledPlugin.String())
			client, cleanup, err := external_plugins.CreateHostPlugin(
				ctx,
				pluginType,
				external_plugins.WithPluginOptions(
					pluginutil.WithPluginExecutionDirectory(conf.RawConfig.Plugins.ExecutionDir),
					pluginutil.WithPluginsFilesystem(boundary_plugin_assets.PluginPrefix, boundary_plugin_assets.FileSystem()),
				),
				external_plugins.WithLogger(pluginLogger.Named(pluginType)),
			)
			if err != nil {
				return nil, fmt.Errorf("error creating %s host plugin: %w", pluginType, err)
			}
			conf.ShutdownFuncs = append(conf.ShutdownFuncs, cleanup)
			if _, err := conf.RegisterPlugin(ctx, pluginType, client, []plugin.PluginType{plugin.PluginTypeHost}, plugin.WithDescription(fmt.Sprintf("Built-in %s host plugin", enabledPlugin.String()))); err != nil {
				return nil, fmt.Errorf("error registering %s host plugin: %w", pluginType, err)
			}
		case enabledPlugin == base.EnabledPluginGCP && !c.conf.SkipPlugins:
			fallthrough
		case enabledPlugin == base.EnabledPluginAws && !c.conf.SkipPlugins:
			pluginType := strings.ToLower(enabledPlugin.String())
			client, cleanup, err := external_plugins.CreateHostPlugin(
				ctx,
				pluginType,
				external_plugins.WithPluginOptions(
					pluginutil.WithPluginExecutionDirectory(conf.RawConfig.Plugins.ExecutionDir),
					pluginutil.WithPluginsFilesystem(boundary_plugin_assets.PluginPrefix, boundary_plugin_assets.FileSystem()),
				),
				external_plugins.WithLogger(pluginLogger.Named(pluginType)),
			)
			if err != nil {
				return nil, fmt.Errorf("error creating %s host plugin: %w", pluginType, err)
			}
			conf.ShutdownFuncs = append(conf.ShutdownFuncs, cleanup)
			if _, err := conf.RegisterPlugin(ctx, pluginType, client, []plugin.PluginType{plugin.PluginTypeHost, plugin.PluginTypeStorage}, plugin.WithDescription(fmt.Sprintf("Built-in %s host plugin", enabledPlugin.String()))); err != nil {
				return nil, fmt.Errorf("error registering %s host plugin: %w", pluginType, err)
			}
		case enabledPlugin == base.EnabledPluginMinio && !c.conf.SkipPlugins:
			pluginType := strings.ToLower(enabledPlugin.String())
			if _, err := conf.RegisterPlugin(ctx, pluginType, nil, []plugin.PluginType{plugin.PluginTypeStorage}, plugin.WithDescription(fmt.Sprintf("Built-in %s storage plugin", enabledPlugin.String()))); err != nil {
				return nil, fmt.Errorf("error registering %s storage plugin: %w", pluginType, err)
			}
		}
	}

	if conf.HostPlugins == nil {
		conf.HostPlugins = make(map[string]plgpb.HostPluginServiceClient)
	}

	// Set up repo stuff
	dbase := db.New(c.conf.Database)
	txManager := db.NewTransactionManager(c.conf.Database)
	c.kms, err = kms.New(ctx, dbase, dbase)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := c.kms.AddExternalWrappers(
		ctx,
		kms.WithRootWrapper(c.conf.RootKms),
		kms.WithWorkerAuthWrapper(c.conf.WorkerAuthKms),
		kms.WithRecoveryWrapper(c.conf.RecoveryKms),
		kms.WithBsrWrapper(c.conf.BsrKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	// we need to get all the scopes so we can reconcile the DEKs for each scope.
	iamRepo, err := iam.NewRepository(ctx, dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
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
		return job.NewRepository(ctx, dbase, dbase, c.kms)
	}

	schedulerOpts := []scheduler.Option{}
	if c.conf.RawConfig.Controller.Scheduler.JobRunIntervalDuration > 0 {
		schedulerOpts = append(schedulerOpts, scheduler.WithRunJobsInterval(c.conf.RawConfig.Controller.Scheduler.JobRunIntervalDuration))
	}
	if c.conf.RawConfig.Controller.Scheduler.MonitorIntervalDuration > 0 {
		schedulerOpts = append(schedulerOpts, scheduler.WithMonitorInterval(c.conf.RawConfig.Controller.Scheduler.MonitorIntervalDuration))
	}

	c.scheduler, err = scheduler.New(ctx, c.conf.RawConfig.Controller.Name, jobRepoFn, schedulerOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating new scheduler: %w", err)
	}
	c.IamRepoFn = func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.StaticHostRepoFn = func() (*static.Repository, error) {
		return static.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.PluginHostRepoFn = func() (*pluginhost.Repository, error) {
		return pluginhost.NewRepository(ctx, dbase, dbase, c.kms, c.scheduler, c.conf.HostPlugins)
	}
	c.PluginRepoFn = func() (*plugin.Repository, error) {
		return plugin.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.PluginStorageBucketRepoFn = func() (*pluginstorage.Repository, error) {
		return pluginstorage.NewRepository(ctx, dbase, dbase, c.kms, c.scheduler)
	}
	c.AuthTokenRepoFn = func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, dbase, dbase, c.kms,
			authtoken.WithTokenTimeToLiveDuration(c.conf.RawConfig.Controller.AuthTokenTimeToLiveDuration),
			authtoken.WithTokenTimeToStaleDuration(c.conf.RawConfig.Controller.AuthTokenTimeToStaleDuration))
	}
	c.VaultCredentialRepoFn = func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, dbase, dbase, c.kms, c.scheduler, vault.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.StaticCredentialRepoFn = func() (*credstatic.Repository, error) {
		return credstatic.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.CredentialStoreRepoFn = func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(ctx, dbase, dbase)
	}
	c.HostCatalogRepoFn = func() (*host.CatalogRepository, error) {
		return host.NewCatalogRepository(ctx, dbase, dbase)
	}
	c.ServersRepoFn = func() (*server.Repository, error) {
		return server.NewRepository(ctx, dbase, dbase, c.kms, server.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.OidcRepoFn = func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.LdapRepoFn = func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(ctx, dbase, dbase, c.kms, password.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.AuthMethodRepoFn = func() (*auth.AuthMethodRepository, error) {
		return auth.NewAuthMethodRepository(ctx, dbase, dbase, c.kms)
	}
	c.TargetRepoFn = func(o ...target.Option) (*target.Repository, error) {
		o = append(o, target.WithRandomReader(c.conf.SecureRandomReader))
		return target.NewRepository(ctx, dbase, dbase, c.kms, o...)
	}
	c.SessionRepoFn = func(opt ...session.Option) (*session.Repository, error) {
		// Always add a secure random reader to the new session repository.
		// Add it as the first option so that it can be overridden by users.
		opt = append([]session.Option{session.WithRandomReader(c.conf.SecureRandomReader)}, opt...)
		return session.NewRepository(ctx, dbase, dbase, c.kms, opt...)
	}
	c.ConnectionRepoFn = func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, dbase, dbase, c.kms)
	}
	c.WorkerAuthRepoStorageFn = func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, dbase, dbase, c.kms)
	}
	c.BillingRepoFn = func() (*billing.Repository, error) {
		return billing.NewRepository(ctx, dbase)
	}
	c.AliasRepoFn = func() (*alias.Repository, error) {
		return alias.NewRepository(ctx, txManager, c.kms)
	}
	c.TargetAliasRepoFn = func() (*talias.Repository, error) {
		return talias.NewRepository(ctx, dbase, dbase, c.kms)
	}

	// Check that credentials are available at startup, to avoid some harmless
	// but nasty-looking errors
	serversRepo, err := server.NewRepositoryStorage(ctx, dbase, dbase, c.kms)
	if err != nil {
		return nil, fmt.Errorf("unable to instantiate worker auth repository: %w", err)
	}
	_, err = server.RotateRoots(ctx, serversRepo, nodeenrollment.WithCertificateLifetime(conf.TestOverrideWorkerAuthCaCertificateLifetime), nodeenrollment.WithReinitializeRoots(conf.TestWorkerAuthCaReinitialize))
	if err != nil {
		event.WriteSysEvent(ctx, op, "unable to ensure worker auth roots exist, may be due to multiple controllers starting at once, continuing")
	}

	if c.conf.RawConfig.Controller.ConcurrentPasswordHashWorkers > 0 {
		if err := password.SetHashingPermits(int(c.conf.RawConfig.Controller.ConcurrentPasswordHashWorkers)); err != nil {
			return nil, fmt.Errorf("unable to set number of concurrent password workers: %w", err)
		}
	}

	if graphFactory != nil {
		boundVer := version.Get().VersionNumber()
		c.downstreamWorkers, err = graphFactory(ctx, "root", boundVer)
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

	if extControllerFactory != nil {
		if c.ControllerExtension, err = extControllerFactory(ctx, c, dbase, dbase, c.kms); err != nil {
			return nil, fmt.Errorf("unable to extend controller: %w", err)
		}
	}

	return c, nil
}

func (c *Controller) Start() error {
	const op = "controller.(Controller).Start"
	if c.started.Swap(true) {
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
	if err := c.startWorkerConnectionMaintenanceTicking(c.baseContext, c.tickerWg, c.downstreamConnManager); err != nil {
		return errors.Wrap(c.baseContext, err, op)
	}

	if c.downstreamConns != nil {
		c.tickerWg.Add(2)

		servNameFn := func() string {
			switch {
			case c.conf.RawConfig.Controller.Name != "":
				return c.conf.RawConfig.Controller.Name
			default:
				return "unknown controller name"
			}
		}
		go func() {
			defer c.tickerWg.Done()
			c.downstreamConns.StartProcessingPendingConnections(c.baseContext, servNameFn)
		}()
		go func() {
			defer c.tickerWg.Done()
			err := c.downstreamConns.StartConnectionMgmtTicking(
				c.baseContext,
				servNameFn,
				-1,
			)
			if err != nil {
				event.WriteError(c.baseContext, op, fmt.Errorf("connection management ticker exited with error: %w", err))
			}
		}()
	}
	if downstreamWorkersTickerFactory != nil {
		// we'll use "root" to designate that this is the root of the graph (aka
		// a controller)
		boundVer := version.Get().VersionNumber()
		dswTicker, err := downstreamWorkersTickerFactory(c.baseContext, "root", boundVer, c.downstreamWorkers, c.downstreamConns, c.getDownstreamWorkersTimeout)
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
	if c.ControllerExtension != nil {
		if err := c.ControllerExtension.Start(c.baseContext); err != nil {
			return fmt.Errorf("error starting controller extension: %w", err)
		}
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
	if err := session.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms, c.workerRPCGracePeriod); err != nil {
		return err
	}
	var serverJobOpts []serversjob.Option
	if c.conf.TestOverrideWorkerAuthCaCertificateLifetime > 0 {
		serverJobOpts = append(serverJobOpts,
			serversjob.WithCertificateLifetime(c.conf.TestOverrideWorkerAuthCaCertificateLifetime),
			serversjob.WithRotationFrequency(c.conf.TestOverrideWorkerAuthCaCertificateLifetime/2),
		)
	}
	if err := serversjob.RegisterJobs(c.baseContext, c.scheduler, rw, rw, c.kms, c.ControllerExtension, c.workerRPCGracePeriod, serverJobOpts...); err != nil {
		return err
	}
	if err := kmsjob.RegisterJobs(c.baseContext, c.scheduler, c.kms); err != nil {
		return err
	}
	if err := snapshot.RegisterJob(c.baseContext, c.scheduler, rw, rw); err != nil {
		return err
	}
	if err := census.RegisterJob(c.baseContext, c.scheduler, c.conf.RawConfig.Reporting.License.Enabled, rw, rw, c.conf.SecureRandomReader); err != nil {
		return err
	}
	if err := purge.RegisterJobs(c.baseContext, c.scheduler, rw, rw); err != nil {
		return err
	}
	if err := recording.RegisterJob(c.baseContext, c.scheduler, rw, rw, c.ControllerExtension, c.kms); err != nil {
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

// WorkerRoutingInfoUpdateTimes returns the map, which specifically is held in _this_
// controller, not the DB. It's used in tests to verify that a given controller
// is receiving updates from an expected set of workers, to test out balancing
// and auto reconnection.
func (c *Controller) WorkerRoutingInfoUpdateTimes() *sync.Map {
	return c.workerRoutingInfoUpdateTimes
}

// ReloadTimings reloads timing related parameters
func (c *Controller) ReloadTimings(newConfig *config.Config) error {
	const op = "controller.(Controller).ReloadTimings"

	switch {
	case newConfig == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config")
	case newConfig.Controller == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config.Controller")
	}

	switch newConfig.Controller.WorkerRPCGracePeriodDuration {
	case 0:
		c.workerRPCGracePeriod.Store(int64(server.DefaultLiveness))
	default:
		c.workerRPCGracePeriod.Store(int64(newConfig.Controller.WorkerRPCGracePeriodDuration))
	}
	switch newConfig.Controller.LivenessTimeToStaleDuration {
	case 0:
		c.livenessTimeToStale.Store(int64(server.DefaultLiveness))
	default:
		c.livenessTimeToStale.Store(int64(newConfig.Controller.LivenessTimeToStaleDuration))
	}

	switch newConfig.Controller.GetDownstreamWorkersTimeoutDuration {
	case 0:
		c.getDownstreamWorkersTimeout.Store(int64(server.DefaultLiveness))
	default:
		c.getDownstreamWorkersTimeout.Store(int64(newConfig.Controller.GetDownstreamWorkersTimeoutDuration))
	}

	return nil
}
