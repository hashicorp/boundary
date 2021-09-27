package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/patrickmn/go-cache"
	ua "go.uber.org/atomic"
)

type Controller struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg    sync.WaitGroup
	schedulerWg sync.WaitGroup

	workerAuthCache *cache.Cache

	// Used for testing and tracking worker health
	workerStatusUpdateTimes *sync.Map

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
}

func New(ctx context.Context, conf *Config) (*Controller, error) {
	c := &Controller{
		conf:                    conf,
		logger:                  conf.Logger.Named("controller"),
		started:                 ua.NewBool(false),
		workerStatusUpdateTimes: new(sync.Map),
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
	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(dbase, dbase, c.kms)
	}
	// TODO: the RunJobsLimit is temporary until a better fix gets in. This
	// currently caps the scheduler at running 10 jobs per interval.
	c.scheduler, err = scheduler.New(c.conf.RawConfig.Controller.Name, jobRepoFn, scheduler.WithRunJobsLimit(10))
	if err != nil {
		return nil, fmt.Errorf("error creating new scheduler: %w", err)
	}
	c.IamRepoFn = func() (*iam.Repository, error) {
		return iam.NewRepository(dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.StaticHostRepoFn = func() (*static.Repository, error) {
		return static.NewRepository(dbase, dbase, c.kms)
	}
	c.PluginHostRepoFn = func() (*hostplugin.Repository, error) {
		return hostplugin.NewRepository(dbase, dbase, c.kms, new(host.PluginMap))
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
	c.workerAuthCache = cache.New(0, 0)

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
	if err := c.scheduler.Start(c.baseContext, &c.schedulerWg); err != nil {
		return fmt.Errorf("error starting scheduler: %w", err)
	}
	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting controller listeners: %w", err)
	}

	c.tickerWg.Add(5)
	go func() {
		defer c.tickerWg.Done()
		c.startStatusTicking(c.baseContext)
	}()
	go func() {
		defer c.tickerWg.Done()
		c.startRecoveryNonceCleanupTicking(c.baseContext)
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
