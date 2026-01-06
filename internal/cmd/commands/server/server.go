// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	atm "sync/atomic"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/cmd/ops"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"go.uber.org/atomic"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

var extraSelfTerminationConditionFuncs []func(*Command, chan struct{})

type Command struct {
	*base.Server
	opsServer *ops.Server

	SighupCh  chan struct{}
	SigUSR2Ch chan struct{}

	Config *config.Config

	schemaManager *schema.Manager
	controller    *controller.Controller
	worker        *worker.Worker

	flagConfig                  []string
	flagConfigKms               string
	flagLogLevel                string
	flagLogFormat               string
	flagCombineLogs             bool
	flagSkipPlugins             bool
	flagSkipAliasTargetCreation bool
	flagWorkerDnsServer         string

	reloadedCh                           chan struct{}  // for tests
	startedCh                            chan struct{}  // for tests
	presetConfig                         *atomic.String // for tests
	flagWorkerAuthWorkerRotationInterval time.Duration  // for tests
	flagWorkerAuthCaCertificateLifetime  time.Duration  // for tests
	flagWorkerAuthCaReinitialize         bool           // for tests
}

func (c *Command) Synopsis() string {
	return "Start a Boundary server"
}

func (c *Command) Help() string {
	helpText := `
Usage: boundary server [options]

  Start a server (controller, worker, or both) with a configuration file:

      $ boundary server -config=/etc/boundary/controller.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&base.StringSliceVar{
		Name:   "config",
		Target: &c.flagConfig,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to the configuration file. Can be specified multiple times for multiple configuration files (only if using HCL format).",
	})

	f.StringVar(&base.StringVar{
		Name:   "config-kms",
		Target: &c.flagConfigKms,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: `Path to a configuration file containing a "kms" block marked for "config" purpose, to perform decryption of the main configuration file. If not set, will look for such a block in the main configuration file, which has some drawbacks; see the help output for "boundary config encrypt -h" for details.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "log-level",
		Target:     &c.flagLogLevel,
		EnvVar:     "BOUNDARY_LOG_LEVEL",
		Completion: complete.PredictSet("trace", "debug", "info", "warn", "err"),
		Usage: "Log verbosity level, mostly as a fallback for events. Supported values (in order of more detail to less) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"err\".",
	})

	f.StringVar(&base.StringVar{
		Name:       "log-format",
		Target:     &c.flagLogFormat,
		Completion: complete.PredictSet("standard", "json"),
		Usage:      `Log format, mostly as a fallback for events. Supported values are "standard" and "json".`,
	})

	f.DurationVar(&base.DurationVar{
		Name:   "worker-auth-worker-rotation-interval",
		Target: &c.flagWorkerAuthWorkerRotationInterval,
		Hidden: true,
	})
	f.DurationVar(&base.DurationVar{
		Name:   "worker-auth-ca-certificate-lifetime",
		Target: &c.flagWorkerAuthCaCertificateLifetime,
		Hidden: true,
	})
	f.BoolVar(&base.BoolVar{
		Name:   "worker-auth-ca-reinitialize",
		Target: &c.flagWorkerAuthCaReinitialize,
		Hidden: true,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-plugins",
		Target: &c.flagSkipPlugins,
		Usage:  "Skip loading compiled-in plugins. This does not prevent loopback plugins from being loaded if enabled.",
		Hidden: true,
	})
	f.StringVar(&base.StringVar{
		Name:   "worker-dns-server",
		Target: &c.flagWorkerDnsServer,
		Usage:  "Use a custom DNS server when workers resolve endpoints.",
		Hidden: true,
	})

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	c.CombineLogs = c.flagCombineLogs

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	if result := c.ParseFlagsAndConfig(args); result > 0 {
		return result
	}

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	serverName, err := os.Hostname()
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to determine hostname: %w", err).Error())
		return base.CommandCliError
	}
	var serverTypes []string
	if c.Config.Controller != nil {
		serverTypes = append(serverTypes, "controller")
	}
	if c.Config.Worker != nil {
		serverTypes = append(serverTypes, "worker")
	}
	serverName = fmt.Sprintf("%s/%s", serverName, strings.Join(serverTypes, "+"))

	if err := c.SetupEventing(c.Context,
		c.Logger,
		c.StderrLock,
		serverName,
		base.WithEventerConfig(c.Config.Eventing),
		base.WithEventGating(true)); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	c.WorkerAuthDebuggingEnabled.Store(c.Config.EnableWorkerAuthDebugging)

	base.StartMemProfiler(c.Context)
	base.StartPprof(c.Context)

	// Note: the checks directly after this must remain where they are because
	// they rely on the state of configured KMSes.
	if err := c.SetupKMSes(c.Context, c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if c.Config.Controller != nil {
		if c.RootKms == nil {
			c.UI.Error("Root KMS not found after parsing KMS blocks")
			return base.CommandUserError
		}
	}
	if c.Config.Worker != nil {
		switch c.WorkerAuthKms {
		case nil:
			if c.Config.Worker.AuthStoragePath == "" {
				c.UI.Error("No worker auth KMS specified and no worker auth storage path specified.")
				return base.CommandUserError
			}
			if c.Config.Worker.Name != "" || c.Config.Worker.Description != "" {
				c.UI.Error("Worker config cannot contain name or description when using activation-token-based worker authentication; it must be set via the API.")
				return base.CommandUserError
			}
		default:
			if c.Config.Worker.Name == "" {
				c.UI.Error("Worker is using KMS auth but has no name set. It must be the unique name of this instance.")
				return base.CommandUserError
			}
			if c.Config.Worker.ControllerGeneratedActivationToken != "" {
				c.UI.Error("Worker has KMS auth info but also has a controller-generated activation token set, which is incompatible.")
				return base.CommandUserError
			}
			if c.Config.Worker.AuthStoragePath != "" {
				c.UI.Error("Worker has KMS auth info but also has an auth storage path set, which is incompatible.")
				return base.CommandUserError
			}
		}
		if c.Config.Controller != nil {
			if c.Config.Worker.Name == c.Config.Controller.Name {
				c.UI.Error("Controller and worker cannot be configured with the same name.")
				return base.CommandUserError
			}
		}
	}

	if c.Config.DefaultMaxRequestDuration != 0 {
		globals.DefaultMaxRequestDuration = c.Config.DefaultMaxRequestDuration
	}

	// If mlockall(2) isn't supported, show a warning. We disable this in dev
	// because it is quite scary to see when first using Boundary. We also disable
	// this if the user has explicitly disabled mlock in configuration.
	if !c.Config.DisableMlock && !mlock.Supported() {
		c.UI.Warn(base.WrapAtLength(
			"WARNING! mlock is not supported on this system! An mlockall(2)-like " +
				"syscall to prevent memory from being swapped to disk is not " +
				"supported on this system. For better security, only run Boundary on " +
				"systems where this call is supported. If you are running Boundary" +
				"in a Docker container, provide the IPC_LOCK cap to the container."))
	}

	c.SkipPlugins = c.flagSkipPlugins
	c.SkipAliasTargetCreation = c.flagSkipAliasTargetCreation
	c.WorkerDnsServer = c.flagWorkerDnsServer

	// Perform controller-specific listener checks here before setup
	var clusterAddr string
	var foundApi bool
	var foundProxy bool
	for _, lnConfig := range c.Config.Listeners {
		switch len(lnConfig.Purpose) {
		case 0:
			c.UI.Error("Listener specified without a purpose")
			return base.CommandUserError

		case 1:
			purpose := lnConfig.Purpose[0]
			switch purpose {
			case "cluster":
				clusterAddr = lnConfig.Address
				if clusterAddr == "" {
					clusterAddr = "127.0.0.1:9201"
					lnConfig.Address = clusterAddr
				}
			case "api":
				foundApi = true
			case "proxy":
				foundProxy = true
				if lnConfig.Address == "" {
					lnConfig.Address = "127.0.0.1:9202"
				}
			case "ops":
			default:
				c.UI.Error(fmt.Sprintf("Unknown listener purpose %q", lnConfig.Purpose[0]))
				return base.CommandUserError
			}

		default:
			c.UI.Error("Specifying a listener with more than one purpose is not supported")
			return base.CommandUserError
		}
	}
	if c.Config.Controller != nil {
		if !foundApi {
			c.UI.Error(`Config activates controller but no listener with "api" purpose found`)
			return base.CommandUserError
		}
		if clusterAddr == "" {
			c.UI.Error(`Config activates controller but no listener with "cluster" purpose found`)
			return base.CommandUserError
		}
		if err := c.Config.SetupControllerPublicClusterAddress(""); err != nil {
			c.UI.Error(err.Error())
			return base.CommandUserError
		}
		c.InfoKeys = append(c.InfoKeys, "controller public cluster addr")
		c.Info["controller public cluster addr"] = c.Config.Controller.PublicClusterAddr
	}

	if c.Config.Worker != nil {
		if !foundProxy {
			c.UI.Error(`Config activates worker but no listener with "proxy" purpose found`)
			return base.CommandUserError
		}

		if err := c.SetupWorkerPublicAddress(c.Config, ""); err != nil {
			c.UI.Error(err.Error())
			return base.CommandUserError
		}
		c.InfoKeys = append(c.InfoKeys, "worker public proxy addr")
		c.Info["worker public proxy addr"] = c.Config.Worker.PublicAddr

		if c.Config.Controller != nil {
			if err := c.Config.SetupWorkerInitialUpstreams(); err != nil {
				c.UI.Error(err.Error())
				return base.CommandUserError
			}
		}
		for _, upstream := range c.Config.Worker.InitialUpstreams {
			host, _, err := util.SplitHostPort(upstream)
			if err != nil && !errors.Is(err, util.ErrMissingPort) {
				c.UI.Error(fmt.Errorf("Invalid worker upstream address %q: %w", upstream, err).Error())
				return base.CommandUserError
			}
			ip := net.ParseIP(host)
			if ip != nil {
				var errMsg string
				switch {
				case ip.IsUnspecified():
					errMsg = "an unspecified"
				case ip.IsMulticast():
					errMsg = "a multicast"
				}
				if errMsg != "" {
					c.UI.Error(fmt.Sprintf("Worker upstream address %q is invalid: cannot be %s address", upstream, errMsg))
					return base.CommandUserError
				}
			}
		}

		if c.Config.HcpbClusterId != "" {
			if len(c.Config.Worker.InitialUpstreams) > 0 {
				c.UI.Error(fmt.Errorf("Initial upstreams and HCPB cluster ID are mutually exclusive fields").Error())
				return base.CommandUserError
			}
			clusterId, err := parseutil.ParsePath(c.Config.HcpbClusterId)
			if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
				c.UI.Error(fmt.Errorf("Failed to parse HCP Boundary cluster ID %q: %w", clusterId, err).Error())
				return base.CommandUserError
			}
			if strings.HasPrefix(clusterId, "int-") {
				clusterId = strings.TrimPrefix(clusterId, "int-")
			} else if strings.HasPrefix(clusterId, "dev-") {
				clusterId = strings.TrimPrefix(clusterId, "dev-")
			}
			_, err = uuid.ParseUUID(clusterId)
			if err != nil {
				c.UI.Error(fmt.Errorf("Invalid HCP Boundary cluster ID %q: %w", clusterId, err).Error())
				return base.CommandUserError
			}
		}
	}
	if err := c.SetupListeners(c.UI, c.Config.SharedConfig, []string{"api", "cluster", "proxy", "ops"}); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	if c.Config.Controller != nil {
		for _, ln := range c.Config.Listeners {
			for _, purpose := range ln.Purpose {
				if purpose != "cluster" {
					continue
				}
				host, _, err := util.SplitHostPort(ln.Address)
				if err != nil && !errors.Is(err, util.ErrMissingPort) {
					c.UI.Error(fmt.Errorf("Invalid cluster listener address %q: %w", ln.Address, err).Error())
					return base.CommandUserError
				}
				ip := net.ParseIP(host)
				if ip != nil {
					if ip.IsUnspecified() && c.Config.Controller.PublicClusterAddr == "" {
						c.UI.Error(fmt.Sprintf("When %q listener has an unspecified address, %q must be set", "cluster", "public_cluster_addr"))
						return base.CommandUserError
					}
				}
			}
		}
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return base.CommandUserError
	}

	if c.Config.Controller != nil {
		if c.Config.Controller.Database == nil || c.Config.Controller.Database.Url == "" {
			c.UI.Error(`"url" not specified in "controller.database" config block"`)
			return base.CommandUserError
		}
		var err error
		c.DatabaseUrl, err = parseutil.ParsePath(c.Config.Controller.Database.Url)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
			return base.CommandUserError
		}
		c.DatabaseMaxOpenConnections = c.Config.Controller.Database.MaxOpenConnections
		c.DatabaseMaxIdleConnections = c.Config.Controller.Database.MaxIdleConnections
		c.DatabaseConnMaxIdleTimeDuration = c.Config.Controller.Database.ConnMaxIdleTimeDuration

		if err := c.OpenAndSetServerDatabase(c.Context, "postgres"); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return base.CommandCliError
		}

		sm, err := acquireSchemaManager(c.Context, c.Server.Database, c.Config.Controller.Database.SkipSharedLockAcquisition)
		if err != nil {
			c.UI.Error(fmt.Errorf("Failed to acquire database shared lock: %w", err).Error())
			return base.CommandCliError
		}
		c.schemaManager = sm

		defer func() {
			if c.schemaManager == nil {
				c.UI.Error("no schema manager to unlock database with")
				return
			}

			// The base context has already been canceled so we shouldn't use it here.
			// 1 second is chosen so the shutdown is still responsive and this is a mostly
			// non critical step since the lock should be released when the session with the
			// database is closed.
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := c.schemaManager.Close(ctx)
			if err != nil {
				c.UI.Error(fmt.Errorf("Unable to release shared lock to the database: %w", err).Error())
			}
		}()

		err = verifyDatabaseState(c.Context, c.Server.Database, c.schemaManager)
		if err != nil {
			c.UI.Error(err.Error())
			return base.CommandCliError
		}

		if c.Config.Controller.Database.SkipSharedLockAcquisition {
			if err := c.schemaManager.Close(c.Context); err != nil {
				c.UI.Error(fmt.Errorf("Unable to release shared lock to the database: %w", err).Error())
				return base.CommandCliError
			}
		}
	}

	c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginAws, base.EnabledPluginHostAzure, base.EnabledPluginGCP)
	if base.MinioEnabled {
		c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginMinio)
	}

	if c.Config.Controller != nil {
		if err := c.StartController(c.Context); err != nil {
			c.UI.Error(err.Error())
			return base.CommandCliError
		}
	}

	if c.Config.Worker != nil {
		if err := c.StartWorker(); err != nil {
			c.UI.Error(err.Error())
			if c.controller != nil {
				if err := c.controller.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
				}
			}
			return base.CommandCliError
		}

		if c.worker.WorkerAuthRegistrationRequest != "" {
			c.InfoKeys = append(c.InfoKeys, "worker auth registration request")
			c.Info["worker auth registration request"] = c.worker.WorkerAuthRegistrationRequest
			c.InfoKeys = append(c.InfoKeys, "worker auth current key id")
			c.Info["worker auth current key id"] = c.worker.WorkerAuthCurrentKeyId.Load()

			// Write the WorkerAuth request to a file
			if err := c.StoreWorkerAuthReq(c.worker.WorkerAuthRegistrationRequest, c.Config.Worker.AuthStoragePath); err != nil {
				// Shutdown on failure
				retErr := fmt.Errorf("Error storing worker auth request: %w", err)
				if err := c.worker.Shutdown(); err != nil {
					c.UI.Error(retErr.Error())
					retErr = fmt.Errorf("Error shutting down worker: %w", err)
				}
				c.UI.Error(retErr.Error())
				if c.controller != nil {
					if err := c.controller.Shutdown(); err != nil {
						c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
					}
				}
				return base.CommandCliError
			}
		}
	}

	c.PrintInfo(c.UI)
	if err := c.ReleaseLogGate(); err != nil {
		c.UI.Error(fmt.Errorf("Error releasing event gate: %w", err).Error())
		return base.CommandCliError
	}

	opsServer, err := ops.NewServer(c.Context, c.Logger, c.controller, c.worker, c.Listeners...)
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}
	c.opsServer = opsServer
	c.opsServer.Start()

	// Inform any tests that the server is ready
	if c.startedCh != nil {
		close(c.startedCh)
	}

	return c.WaitForInterrupt()
}

func (c *Command) ParseFlagsAndConfig(args []string) int {
	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	if len(c.flagConfig) == 0 && c.presetConfig == nil {
		c.UI.Error("Must specify a config file using -config")
		return base.CommandUserError
	}

	cfg, out := c.reloadConfig()
	if out > 0 {
		return out
	}

	if extraConfigValidationFunc != nil {
		if err := extraConfigValidationFunc(cfg); err != nil {
			c.UI.Error(err.Error())
			return base.CommandUserError
		}
	}

	c.Config = cfg

	return base.CommandSuccess
}

func (c *Command) reloadConfig() (*config.Config, int) {
	const op = "server.(Command).reloadConfig"

	var err error
	var cfg *config.Config
	switch {
	case c.presetConfig != nil:
		cfg, err = config.Parse(c.presetConfig.Load())
		if err != nil {
			event.WriteError(c.Context, op, err, event.WithInfoMsg("could not parse presetConfig", "config", c.presetConfig))
			return nil, base.CommandUserError
		}

	default:
		cfg, err = config.Load(c.Context, c.flagConfig, c.flagConfigKms)
		if err != nil {
			c.UI.Error("Error parsing config: " + err.Error())
			return nil, base.CommandUserError
		}
	}

	return cfg, 0
}

func (c *Command) StartController(ctx context.Context) error {
	conf := &controller.Config{
		RawConfig: c.Config,
		Server:    c.Server,
		TestOverrideWorkerAuthCaCertificateLifetime: c.flagWorkerAuthCaCertificateLifetime,
		TestWorkerAuthCaReinitialize:                c.flagWorkerAuthCaReinitialize,
	}

	var err error
	c.controller, err = controller.New(ctx, conf)
	if err != nil {
		return fmt.Errorf("Error initializing controller: %w", err)
	}

	if err := c.controller.Start(); err != nil {
		retErr := fmt.Errorf("Error starting controller: %w", err)
		if err := c.controller.Shutdown(); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error shutting down controller: %w", err)
		}
		return retErr
	}

	return nil
}

func (c *Command) StartWorker() error {
	conf := &worker.Config{
		RawConfig: c.Config,
		Server:    c.Server,
	}

	var err error
	c.worker, err = worker.New(c.Context, conf)
	if err != nil {
		return fmt.Errorf("Error initializing worker: %w", err)
	}
	c.worker.TestOverrideAuthRotationPeriod = c.flagWorkerAuthWorkerRotationInterval

	if err := c.worker.Start(); err != nil {
		retErr := fmt.Errorf("Error starting worker: %w", err)
		if err := c.worker.Shutdown(); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error shutting down worker: %w", err)
		}
		return retErr
	}

	if c.WorkerAuthKms == nil {
		if c.worker.WorkerAuthStorage == nil {
			return fmt.Errorf("Chosen worker authentication method requires storage and no worker auth storage was configured")
		}
		c.InfoKeys = append(c.InfoKeys, "worker auth storage path")
		c.Info["worker auth storage path"] = c.Config.Worker.AuthStoragePath
	}

	return nil
}

func (c *Command) WaitForInterrupt() int {
	const op = "server.(Command).WaitForInterrupt"

	var shutdownCompleted atm.Bool
	shutdownTriggerCount := 0

	var workerShutdownOnce sync.Once
	workerShutdownFunc := func() {
		if err := c.worker.Shutdown(); err != nil {
			c.UI.Error(fmt.Errorf("Error shutting down worker: %w", err).Error())
		}
	}
	workerGracefulShutdownFunc := func() {
		if err := c.worker.GracefulShutdown(); err != nil {
			c.UI.Error(fmt.Errorf("Error shutting down worker gracefully: %w", err).Error())
		}
		workerShutdownOnce.Do(workerShutdownFunc)
	}
	var controllerOnce sync.Once
	controllerShutdownFunc := func() {
		if err := c.controller.Shutdown(); err != nil {
			c.UI.Error(fmt.Errorf("Error shutting down controller: %w", err).Error())
		}
		if c.opsServer != nil {
			err := c.opsServer.Shutdown()
			if err != nil {
				c.UI.Error(fmt.Errorf("Failed to shutdown ops listeners: %w", err).Error())
			}
		}
	}

	runShutdownLogic := func() {
		switch {
		case shutdownTriggerCount == 1:
			c.ContextCancel()
			go func() {
				if c.Config.Controller != nil && c.opsServer != nil {
					c.opsServer.WaitIfHealthExists(c.Config.Controller.GracefulShutdownWaitDuration, c.UI)
				}

				if c.Config.Worker != nil {
					c.UI.Output("==> Boundary server graceful shutdown triggered, interrupt again to enter shutdown")
					workerGracefulShutdownFunc()
				} else {
					c.UI.Output("==> Boundary server shutdown triggered, interrupt again to force")
				}

				if c.Config.Controller != nil {
					controllerOnce.Do(controllerShutdownFunc)
				}
				shutdownCompleted.Store(true)
			}()

		case shutdownTriggerCount == 2 && c.Config.Worker != nil:
			go func() {
				if c.Config.Worker != nil {
					workerShutdownOnce.Do(workerShutdownFunc)
				}
				if c.Config.Controller != nil {
					controllerOnce.Do(controllerShutdownFunc)
				}
				shutdownCompleted.Store(true)
			}()

		case shutdownTriggerCount >= 2:
			c.UI.Error("Forcing shutdown")
			os.Exit(base.CommandCliError)
		}
	}

	for _, f := range extraSelfTerminationConditionFuncs {
		f(c, c.ServerSideShutdownCh)
	}

	for !shutdownCompleted.Load() {
		select {
		case <-c.ServerSideShutdownCh:
			c.UI.Output("==> Boundary server self-terminating")
			shutdownTriggerCount++
			runShutdownLogic()

		case <-c.ShutdownCh:
			shutdownTriggerCount++
			runShutdownLogic()

		case <-c.SighupCh:
			c.UI.Output("==> Boundary server reload triggered")

			// Check for new log level
			var level hclog.Level
			var newConf *config.Config
			var out int

			if len(c.flagConfig) == 0 && c.presetConfig == nil {
				goto RUNRELOADFUNCS
			}

			newConf, out = c.reloadConfig()
			if out > 0 {
				goto RUNRELOADFUNCS
			}

			// Ensure at least one config was found.
			if newConf == nil {
				event.WriteError(context.TODO(), op, stderrors.New("no config found at reload time"))
				goto RUNRELOADFUNCS
			}

			if newConf.LogLevel != "" {
				configLogLevel := strings.ToLower(strings.TrimSpace(newConf.LogLevel))
				switch configLogLevel {
				case "trace":
					level = hclog.Trace
				case "debug":
					level = hclog.Debug
				case "notice", "info", "":
					level = hclog.Info
				case "warn", "warning":
					level = hclog.Warn
				case "err", "error":
					level = hclog.Error
				default:
					event.WriteError(context.TODO(), op, stderrors.New("unknown log level found on reload"), event.WithInfo("level", newConf.LogLevel))
					goto RUNRELOADFUNCS
				}
				c.Logger.SetLevel(level)
			}

			c.WorkerAuthDebuggingEnabled.Store(newConf.EnableWorkerAuthDebugging)

		RUNRELOADFUNCS:
			if err := c.Reload(newConf); err != nil {
				c.UI.Error(fmt.Errorf("Error(s) were encountered during reload: %w", err).Error())
			}

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			event.WriteSysEvent(context.TODO(), op, "goroutine trace", "stack", string(buf[:n]))

		case <-time.After(10 * time.Millisecond):
		}
	}

	return base.CommandSuccess
}

func (c *Command) Reload(newConf *config.Config) error {
	c.ReloadFuncsLock.RLock()
	defer c.ReloadFuncsLock.RUnlock()

	var reloadErrors error

	for _, relFunc := range c.ReloadFuncs["listeners"] {
		if relFunc != nil {
			if err := relFunc(); err != nil {
				reloadErrors = stderrors.Join(reloadErrors, fmt.Errorf("error encountered reloading listener: %w", err))
			}
		}
	}

	err := c.reloadControllerDatabase(newConf)
	if err != nil {
		reloadErrors = stderrors.Join(reloadErrors, fmt.Errorf("failed to reload controller database: %w", err))
	}

	if err := c.reloadControllerRateLimits(newConf); err != nil {
		reloadErrors = stderrors.Join(reloadErrors, fmt.Errorf("failed to reload controller api rate limits: %w", err))
	}

	if err := c.reloadControllerTimings(newConf); err != nil {
		reloadErrors = stderrors.Join(reloadErrors, fmt.Errorf("failed to reload controller timings: %w", err))
	}

	if newConf != nil && c.worker != nil {
		workerReloadErr := func() error {
			if newConf.Controller != nil {
				if err := newConf.SetupControllerPublicClusterAddress(""); err != nil {
					return err
				}
			}

			if err := newConf.SetupWorkerInitialUpstreams(); err != nil {
				return err
			}
			c.worker.Reload(c.Context, newConf)
			return nil
		}()
		if workerReloadErr != nil {
			reloadErrors = stderrors.Join(reloadErrors, fmt.Errorf("error encountered reloading worker initial upstreams: %w", workerReloadErr))
		}
	}

	if newConf != nil && newConf.Controller != nil && newConf.Controller.ConcurrentPasswordHashWorkers > 0 {
		reloadErrors = stderrors.Join(reloadErrors, password.SetHashingPermits(int(newConf.Controller.ConcurrentPasswordHashWorkers)))
	}

	// Send a message that we reloaded. This prevents "guessing" sleep times
	// in tests.
	if c.reloadedCh != nil {
		select {
		case c.reloadedCh <- struct{}{}:
		default:
		}
	}

	return reloadErrors
}

func verifyKmsSetup(dbase *db.DB) error {
	const op = "server.(Command).verifyKmsExists"
	rw := db.New(dbase)

	ctx := context.Background()
	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return fmt.Errorf("%s: error creating kms: %w", op, err)
	}
	if err := kmsCache.VerifyGlobalRoot(ctx); err != nil {
		return err
	}
	return nil
}

func (c *Command) reloadControllerDatabase(newConfig *config.Config) error {
	if c.Server == nil || c.Server.Database == nil {
		return nil
	}
	if c.controller == nil {
		return nil
	}
	if newConfig == nil || newConfig.Controller == nil || newConfig.Controller.Database == nil {
		return nil
	}

	var err error
	newConfig.Controller.Database.Url, err = parseutil.ParsePath(newConfig.Controller.Database.Url)
	if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
		return fmt.Errorf("failed to parse db url: %w", err)
	}
	if len(newConfig.Controller.Database.Url) == 0 || c.DatabaseUrl == newConfig.Controller.Database.Url {
		return nil
	}

	newDb, err := c.Server.OpenDatabase(c.Context, "postgres", newConfig.Controller.Database.Url)
	if err != nil {
		return fmt.Errorf("failed to open connection to new database: %w", err)
	}

	// Acquire new lock on the new database and verify that it's in a good state to be used.
	newDbSchemaManager, err := acquireSchemaManager(c.Context, newDb, c.Config.Controller.Database.SkipSharedLockAcquisition)
	if err != nil {
		_ = newDb.Close(c.Context)
		return fmt.Errorf("failed to acquire shared lock on new database: %w", err)
	}

	err = verifyDatabaseState(c.Context, newDb, newDbSchemaManager)
	if err != nil {
		_ = newDbSchemaManager.Close(c.Context)
		_ = newDb.Close(c.Context)
		return fmt.Errorf("invalid new database state: %w", err)
	}

	if newConfig.Controller.Database.SkipSharedLockAcquisition {
		if err := newDbSchemaManager.Close(c.Context); err != nil {
			return fmt.Errorf("unable to release shared lock to the database for new schema manager: %w", err)
		}
	}

	oldDbSchemaManager := c.schemaManager

	// Swap underlying database with new one and update application state.
	oldDbCloseFn, err := c.Database.Swap(c.Context, newDb)
	if err != nil {
		_ = newDbSchemaManager.Close(c.Context)
		_ = newDb.Close(c.Context)
		return fmt.Errorf("failed to swap databases: %w", err)
	}
	c.schemaManager = newDbSchemaManager
	c.Server.DatabaseUrl = newConfig.Controller.Database.Url
	c.Config.Controller.Database.Url = newConfig.Controller.Database.Url

	// Release old database shared lock and close old database object.
	_ = oldDbSchemaManager.Close(c.Context)
	oldDbCloseFn(c.Context)

	return nil
}

func (c *Command) reloadControllerRateLimits(newConfig *config.Config) error {
	if c.controller == nil || newConfig == nil || newConfig.Controller == nil {
		return nil
	}
	return c.controller.ReloadRateLimiter(newConfig)
}

func (c *Command) reloadControllerTimings(newConfig *config.Config) error {
	if c.controller == nil || newConfig == nil || newConfig.Controller == nil {
		return nil
	}

	return c.controller.ReloadTimings(newConfig)
}

// acquireSchemaManager returns a schema manager and generally acquires a shared lock on
// the database. This is done as a mechanism to disallow running migration commands
// while the database is in use.
func acquireSchemaManager(ctx context.Context, db *db.DB, skipSharedLock bool) (*schema.Manager, error) {
	if db == nil {
		return nil, fmt.Errorf("nil database")
	}

	underlyingDb, err := db.SqlDB(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain sql db: %w", err)
	}

	manager, err := schema.NewManager(ctx, "postgres", underlyingDb)
	if err != nil {
		return nil, fmt.Errorf("failed to create new schema manager: %w", err)
	}

	// This is an advisory locks on the DB which is released when the db session ends.
	if !skipSharedLock {
		err = manager.SharedLock(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to gain shared access to the database: %w", err)
		}
	}

	return manager, nil
}

// verifyDatabaseState checks that the migrations and kms setup for the given database are correctly setup.
func verifyDatabaseState(ctx context.Context, db *db.DB, schemaManager *schema.Manager) error {
	if db == nil {
		return fmt.Errorf("nil database")
	}
	if schemaManager == nil {
		return fmt.Errorf("nil schema manager")
	}

	s, err := schemaManager.CurrentState(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current schema state: %w", err)
	}
	if !s.Initialized {
		return fmt.Errorf("The database has not been initialized. Please ensure your database user " +
			"has access to all Boundary tables, or run 'boundary database init' if you haven't initialized " +
			"your database for Boundary.")
	}
	if !s.MigrationsApplied() {
		for _, e := range s.Editions {
			if e.DatabaseSchemaState == schema.Ahead {
				return fmt.Errorf("Newer schema version (%s %d) "+
					"than this binary expects. Please use a newer version of the boundary "+
					"binary.", e.Name, e.DatabaseSchemaVersion)
			}
		}
		return fmt.Errorf("Database schema must be updated to use this version. " +
			"Run 'boundary database migrate' to update the database. " +
			"NOTE: Boundary does not currently support live migration; " +
			"Ensure all controllers are shut down before running the migration command.")
	}

	err = verifyKmsSetup(db)
	if err != nil {
		return fmt.Errorf("Database is in a bad state. Please revert the database "+
			"into the last known good state. (Failed to verify kms setup: %w)", err)
	}

	return nil
}

var extraConfigValidationFunc = func(cfg *config.Config) error {
	if cfg.Controller == nil && cfg.Worker == nil {
		return stderrors.New("Neither worker nor controller specified in configuration file.")
	}
	if cfg.Controller != nil && cfg.Controller.Name == "" {
		return stderrors.New("Controller has no name set. It must be the unique name of this instance.")
	}
	return nil
}
