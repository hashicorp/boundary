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
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	pluginhost "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/plugin/host"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	host_plugin_assets "github.com/hashicorp/boundary/plugins/host"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	external_host_plugins "github.com/hashicorp/boundary/sdk/plugins/host"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc"
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

	apiListeners    []*base.ServerListener
	clusterListener *base.ServerListener

	// Used for testing and tracking worker health
	workerStatusUpdateTimes *sync.Map

	apiGrpcServer         *grpc.Server
	apiGrpcServerListener grpcServerListener
	apiGrpcGatewayTicket  string

	// Repo factory methods
	AuthTokenRepoFn       common.AuthTokenRepoFactory
	VaultCredentialRepoFn common.VaultCredentialRepoFactory
	IamRepoFn             common.IamRepoFactory
	OidcRepoFn            common.OidcAuthRepoFactory
	PasswordAuthRepoFn    common.PasswordAuthRepoFactory
	ServersRepoFn         common.ServersRepoFactory
	SessionRepoFn         common.SessionRepoFactory
	StaticHostRepoFn      common.StaticRepoFactory
	PluginHostRepoFn      common.PluginHostRepoFactory
	HostPluginRepoFn      common.HostPluginRepoFactory
	TargetRepoFn          common.TargetRepoFactory

	scheduler *scheduler.Scheduler

	kms *kms.Kms

	enabledPlugins []base.EnabledPlugin
}

func New(ctx context.Context, conf *Config) (*Controller, error) {
	c := &Controller{
		conf:                    conf,
		logger:                  conf.Logger.Named("controller"),
		started:                 ua.NewBool(false),
		tickerWg:                new(sync.WaitGroup),
		schedulerWg:             new(sync.WaitGroup),
		workerAuthCache:         new(sync.Map),
		workerStatusUpdateTimes: new(sync.Map),
		enabledPlugins:          conf.Server.EnabledPlugins,
	}

	c.started.Store(false)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Controller == nil {
		conf.RawConfig.Controller = new(config.Controller)
	}

	if conf.RawConfig.Controller.Name, err = conf.RawConfig.Controller.InitNameIfEmpty(); err != nil {
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

	for _, enabledPlugin := range c.enabledPlugins {
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
				external_host_plugins.WithHostPluginsFilesystem("boundary-plugin-host-", host_plugin_assets.FileSystem()),
				external_host_plugins.WithHostPluginExecutionDir(conf.RawConfig.Plugins.ExecutionDir),
				external_host_plugins.WithLogger(hclog.NewNullLogger()))
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
	kmsRepo, err := kms.NewRepository(dbase, dbase)
	if err != nil {
		return nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	c.kms, err = kms.NewKms(kmsRepo)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := c.kms.AddExternalWrappers(
		kms.WithRootWrapper(c.conf.RootKms),
		kms.WithWorkerAuthWrapper(c.conf.WorkerAuthKms),
		kms.WithRecoveryWrapper(c.conf.RecoveryKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}
	if err := c.kms.ReconcileKeys(ctx, c.conf.SecureRandomReader); err != nil {
		return nil, fmt.Errorf("error reconciling kms keys: %w", err)
	}

	// now that the kms is configured, we can get the audit wrapper and rotate
	// the eventer audit wrapper, so the emitted events can include encrypt and
	// hmac-sha256 data
	auditWrapper, err := c.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeAudit)
	if err != nil {
		return nil, fmt.Errorf("error getting audit wrapper from kms: %w", err)
	}
	if c.conf.Eventer.RotateAuditWrapper(ctx, auditWrapper); err != nil {
		return nil, fmt.Errorf("error rotating eventer audit wrapper: %w", err)
	}
	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(dbase, dbase, c.kms)
	}
	// TODO: the RunJobsLimit is temporary until a better fix gets in. This
	// currently caps the scheduler at running 10 jobs per interval.
	schedulerOpts := []scheduler.Option{scheduler.WithRunJobsLimit(10)}
	if c.conf.RawConfig.Controller.SchedulerRunJobInterval > 0 {
		schedulerOpts = append(schedulerOpts, scheduler.WithRunJobsInterval(c.conf.RawConfig.Controller.SchedulerRunJobInterval))
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
	c.ServersRepoFn = func() (*servers.Repository, error) {
		return servers.NewRepository(dbase, dbase, c.kms)
	}
	c.OidcRepoFn = func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, dbase, dbase, c.kms)
	}
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(dbase, dbase, c.kms)
	}
	c.TargetRepoFn = func() (*target.Repository, error) {
		return target.NewRepository(dbase, dbase, c.kms)
	}
	c.SessionRepoFn = func() (*session.Repository, error) {
		return session.NewRepository(dbase, dbase, c.kms)
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

	if err := c.registerSessionCleanupJob(); err != nil {
		return err
	}

	return nil
}

// registerSessionCleanupJob is a helper method to abstract
// registering the session cleanup job specifically.
func (c *Controller) registerSessionCleanupJob() error {
	sessionCleanupJob, err := newSessionCleanupJob(c.SessionRepoFn, int(c.conf.StatusGracePeriodDuration.Seconds()))
	if err != nil {
		return fmt.Errorf("error creating session cleanup job: %w", err)
	}
	if err = c.scheduler.RegisterJob(c.baseContext, sessionCleanupJob); err != nil {
		return fmt.Errorf("error registering session cleanup job: %w", err)
	}

	return nil
}

func (c *Controller) Shutdown(serversOnly bool) error {
	const op = "controller.(Controller).Shutdown"
	if !c.started.Load() {
		event.WriteSysEvent(context.TODO(), op, "already shut down, skipping")
	}
	defer c.started.Store(false)
	c.baseCancel()
	if err := c.stopListeners(serversOnly); err != nil {
		return fmt.Errorf("error stopping controller listeners: %w", err)
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
