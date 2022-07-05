package server

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/cmd/ops"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"go.uber.org/atomic"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Server
	opsServer *ops.Server

	SighupCh  chan struct{}
	SigUSR2Ch chan struct{}

	Config     *config.Config
	controller *controller.Controller
	worker     *worker.Worker

	flagConfig      string
	flagConfigKms   string
	flagLogLevel    string
	flagLogFormat   string
	flagCombineLogs bool

	reloadedCh   chan struct{}  // for tests
	startedCh    chan struct{}  // for tests
	presetConfig *atomic.String // for tests
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

	f.StringVar(&base.StringVar{
		Name:   "config",
		Target: &c.flagConfig,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to the configuration file.",
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
		Usage: "Log verbosity level. Supported values (in order of more detail to less) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"err\".",
	})

	f.StringVar(&base.StringVar{
		Name:       "log-format",
		Target:     &c.flagLogFormat,
		Completion: complete.PredictSet("standard", "json"),
		Usage:      `Log format. Supported values are "standard" and "json".`,
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

	if err := c.SetupEventing(c.Logger,
		c.StderrLock,
		serverName,
		base.WithEventerConfig(c.Config.Eventing),
		base.WithEventGating(true)); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	// Initialize status grace period (0 denotes using env or default
	// here)
	c.SetStatusGracePeriodDuration(0)

	base.StartMemProfiler(c.Context)

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
				c.UI.Error("Worker config cannot contain name or description when using PKI-based worker authentication; it must be set via the API.")
				return base.CommandUserError
			}
		default:
			if c.Config.Worker.Name == "" {
				c.UI.Error("Worker is using KMS auth but has no name set. It must be the unique name of this instance.")
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
		if err := c.SetupControllerPublicClusterAddress(c.Config, ""); err != nil {
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
		if c.Config.Worker.ControllersRaw != nil {
			c.UI.Warn("The \"controllers\" field for worker config is deprecated. Please use \"initial_upstreams\" instead.")
		}

		if err := c.SetupWorkerPublicAddress(c.Config, ""); err != nil {
			c.UI.Error(err.Error())
			return base.CommandUserError
		}
		c.InfoKeys = append(c.InfoKeys, "worker public proxy addr")
		c.Info["worker public proxy addr"] = c.Config.Worker.PublicAddr

		if c.Config.Controller != nil {
			switch len(c.Config.Worker.InitialUpstreams) {
			case 0:
				if c.Config.Controller.PublicClusterAddr != "" {
					clusterAddr = c.Config.Controller.PublicClusterAddr
				}
				c.Config.Worker.InitialUpstreams = []string{clusterAddr}
			case 1:
				if c.Config.Worker.InitialUpstreams[0] == clusterAddr {
					break
				}
				if c.Config.Controller.PublicClusterAddr != "" &&
					c.Config.Worker.InitialUpstreams[0] == c.Config.Controller.PublicClusterAddr {
					break
				}
				// Best effort see if it's a domain name and if not assume it must match
				host, _, err := net.SplitHostPort(c.Config.Worker.InitialUpstreams[0])
				if err != nil && strings.Contains(err.Error(), "missing port in address") {
					err = nil
					host = c.Config.Worker.InitialUpstreams[0]
				}
				if err == nil {
					ip := net.ParseIP(host)
					if ip == nil {
						// Assume it's a domain name
						break
					}
				}
				fallthrough
			default:
				c.UI.Error(`When running a combined controller and worker, it's invalid to specify a "initial_upstreams" or "controllers" key in the worker block with any values other than the controller cluster or upstream worker address/port when using IPs rather than DNS names`)
				return base.CommandUserError
			}
		}
		for _, upstream := range c.Config.Worker.InitialUpstreams {
			host, _, err := net.SplitHostPort(upstream)
			if err != nil {
				if strings.Contains(err.Error(), "missing port in address") {
					host = upstream
				} else {
					c.UI.Error(fmt.Errorf("Invalid worker upstream address %q: %w", upstream, err).Error())
					return base.CommandUserError
				}
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
			_, err := uuid.ParseUUID(c.Config.HcpbClusterId)
			if err != nil {
				c.UI.Error(fmt.Errorf("Invalid HCP Boundary cluster id %q: %w", c.Config.HcpbClusterId, err).Error())
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
				host, _, err := net.SplitHostPort(ln.Address)
				if err != nil {
					if strings.Contains(err.Error(), "missing port in address") {
						host = ln.Address
					} else {
						c.UI.Error(fmt.Errorf("Invalid cluster listener address %q: %w", ln.Address, err).Error())
						return base.CommandUserError
					}
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

		if err := c.ConnectToDatabase(c.Context, "postgres"); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return base.CommandCliError
		}

		underlyingDB, err := c.Database.SqlDB(c.Context)
		if err != nil {
			c.UI.Error(fmt.Errorf("Can't get db: %w.", err).Error())
			return base.CommandCliError
		}
		sMan, err := schema.NewManager(c.Context, "postgres", underlyingDB)
		if err != nil {
			c.UI.Error(fmt.Errorf("Can't get schema manager: %w.", err).Error())
			return base.CommandCliError
		}
		// This is an advisory locks on the DB which is released when the db session ends.
		if err := sMan.SharedLock(c.Context); err != nil {
			c.UI.Error(fmt.Errorf("Unable to gain shared access to the database: %w", err).Error())
			return base.CommandCliError
		}
		defer func() {
			// The base context has already been canceled so we shouldn't use it here.
			// 1 second is chosen so the shutdown is still responsive and this is a mostly
			// non critical step since the lock should be released when the session with the
			// database is closed.
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := sMan.SharedUnlock(ctx); err != nil {
				c.UI.Error(fmt.Errorf("Unable to release shared lock to the database: %w", err).Error())
			}
		}()
		ckState, err := sMan.CurrentState(c.Context)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error checking schema state: %w", err).Error())
			return base.CommandCliError
		}
		if !ckState.Initialized {
			c.UI.Error(base.WrapAtLength("The database has not been initialized. Please run 'boundary database init'."))
			return base.CommandCliError
		}
		if !ckState.MigrationsApplied() {
			for _, e := range ckState.Editions {
				if e.DatabaseSchemaState == schema.Ahead {
					c.UI.Error(base.WrapAtLength(fmt.Sprintf("Newer schema version (%s %d) "+
						"than this binary expects. Please use a newer version of the boundary "+
						"binary.", e.Name, e.DatabaseSchemaVersion)))
					return base.CommandCliError
				}
			}
			c.UI.Error(base.WrapAtLength("Database schema must be updated to use this version. Run 'boundary database migrate' to update the database. NOTE: Boundary does not currently support live migration; ensure all controllers are shut down before running the migration command."))
			return base.CommandCliError
		}
		if err := c.verifyKmsSetup(); err != nil {
			c.UI.Error(base.WrapAtLength("Database is in a bad state. Please revert the database into the last known good state."))
			return base.CommandCliError
		}
	}

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	if c.Config.Controller != nil {
		c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginHostAws, base.EnabledPluginHostAzure)
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
			if err := c.StoreWorkerAuthReq(c.worker.WorkerAuthRegistrationRequest, c.worker.WorkerAuthStorage.BaseDir()); err != nil {
				// Shutdown on failure
				retErr := fmt.Errorf("Error storing worker auth request: %w", err)
				if err := c.worker.Shutdown(); err != nil {
					c.UI.Error(retErr.Error())
					retErr = fmt.Errorf("Error shutting down worker: %w", err)
				}
				c.UI.Error(retErr.Error())
				if err := c.controller.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
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

	opsServer, err := ops.NewServer(c.Logger, c.controller, c.Listeners...)
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
	c.Config = cfg

	if c.Config.Controller == nil && c.Config.Worker == nil {
		c.UI.Error("Neither worker nor controller specified in configuration file.")
		return base.CommandUserError
	}
	if c.Config.Controller != nil && c.Config.Controller.Name == "" {
		c.UI.Error("Controller has no name set. It must be the unique name of this instance.")
		return base.CommandUserError
	}

	return base.CommandSuccess
}

func (c *Command) reloadConfig() (*config.Config, int) {
	const op = "server.(Command).reloadConfig"

	var err error
	var cfg *config.Config
	switch {
	case c.presetConfig != nil:
		cfg, err = config.Parse(c.presetConfig.Load())

	default:
		wrapperPath := c.flagConfig
		if c.flagConfigKms != "" {
			wrapperPath = c.flagConfigKms
		}
		var configWrapper wrapping.Wrapper
		var ifWrapper wrapping.InitFinalizer
		var cleanupFunc func() error
		if wrapperPath != "" {
			configWrapper, cleanupFunc, err = wrapper.GetWrapperFromPath(
				c.Context,
				wrapperPath,
				globals.KmsPurposeConfig,
				configutil.WithPluginOptions(
					pluginutil.WithPluginsMap(kms_plugin_assets.BuiltinKmsPlugins()),
					pluginutil.WithPluginsFilesystem(kms_plugin_assets.KmsPluginPrefix, kms_plugin_assets.FileSystem()),
				),
				// TODO: How would we want to expose this kind of log to users when
				// using recovery configs? Generally with normal CLI commands we
				// don't print out all of these logs. We may want a logger with a
				// custom writer behind our existing gate where we print nothing
				// unless there is an error, then dump all of it.
				configutil.WithLogger(hclog.NewNullLogger()),
			)
			if err != nil {
				event.WriteError(c.Context, op, err, event.WithInfoMsg("could not get kms wrapper from config", "path", c.flagConfig))
				return nil, base.CommandUserError
			}
			if cleanupFunc != nil {
				defer func() {
					if err := cleanupFunc(); err != nil {
						event.WriteError(c.Context, op, err, event.WithInfoMsg("could not clean up kms wrapper", "path", c.flagConfig))
					}
				}()
			}
			if configWrapper != nil {
				ifWrapper, _ = configWrapper.(wrapping.InitFinalizer)
			}
		}
		if ifWrapper != nil {
			if err := ifWrapper.Init(c.Context); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
				event.WriteError(c.Context, op, err, event.WithInfoMsg("could not initialize kms", "path", c.flagConfig))
				return nil, base.CommandCliError
			}
		}
		cfg, err = config.LoadFile(c.flagConfig, configWrapper)
		if ifWrapper != nil {
			if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
				event.WriteError(context.Background(), op, err, event.WithInfoMsg("could not finalize kms", "path", c.flagConfig))
				return nil, base.CommandCliError
			}
		}
	}
	if err != nil {
		event.WriteError(c.Context, op, err, event.WithInfoMsg("could not parse config", "path", c.flagConfig))
		return nil, base.CommandUserError
	}
	return cfg, 0
}

func (c *Command) StartController(ctx context.Context) error {
	conf := &controller.Config{
		RawConfig: c.Config,
		Server:    c.Server,
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
	c.worker, err = worker.New(conf)
	if err != nil {
		return fmt.Errorf("Error initializing worker: %w", err)
	}

	if err := c.worker.Start(); err != nil {
		retErr := fmt.Errorf("Error starting worker: %w", err)
		if err := c.worker.Shutdown(); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error shutting down worker: %w", err)
		}
		return retErr
	}

	if c.WorkerAuthKms == nil || c.DevUsePkiForUpstream {
		if c.worker.WorkerAuthStorage == nil {
			return fmt.Errorf("No worker auth storage found")
		}
		c.InfoKeys = append(c.InfoKeys, "worker auth storage path")
		c.Info["worker auth storage path"] = c.worker.WorkerAuthStorage.BaseDir()
	}

	return nil
}

func (c *Command) WaitForInterrupt() int {
	const op = "server.(Command).WaitForInterrupt"
	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> Boundary server shutdown triggered, interrupt again to force")

			// Add a force-shutdown goroutine to consume another interrupt
			abortForceShutdownCh := make(chan struct{})
			defer close(abortForceShutdownCh)
			go func() {
				shutdownCh := make(chan os.Signal, 4)
				signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
				select {
				case <-shutdownCh:
					c.UI.Error("Second interrupt received, forcing shutdown")
					os.Exit(base.CommandUserError)
				case <-abortForceShutdownCh:
					// No-op, we just use this to shut down the goroutine
				}
			}()

			if c.Config.Controller != nil {
				c.opsServer.WaitIfHealthExists(c.Config.Controller.GracefulShutdownWaitDuration, c.UI)
			}

			// Do worker shutdown
			if c.Config.Worker != nil {
				if err := c.worker.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error shutting down worker: %w", err).Error())
				}
			}

			// Do controller shutdown
			if c.Config.Controller != nil {
				if err := c.controller.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error shutting down controller: %w", err).Error())
				}
			}

			err := c.opsServer.Shutdown()
			if err != nil {
				c.UI.Error(fmt.Errorf("Error shutting down ops listeners: %w", err).Error())
			}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Boundary server reload triggered")

			// Check for new log level
			var level hclog.Level
			var newConf *config.Config
			var out int

			if c.flagConfig == "" && c.presetConfig == nil {
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

		RUNRELOADFUNCS:
			if err := c.Reload(newConf); err != nil {
				c.UI.Error(fmt.Errorf("Error(s) were encountered during reload: %w", err).Error())
			}

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			event.WriteSysEvent(context.TODO(), op, "goroutine trace", "stack", string(buf[:n]))
		}
	}

	return base.CommandSuccess
}

func (c *Command) Reload(newConf *config.Config) error {
	c.ReloadFuncsLock.RLock()
	defer c.ReloadFuncsLock.RUnlock()

	var reloadErrors *multierror.Error

	for _, relFunc := range c.ReloadFuncs["listeners"] {
		if relFunc != nil {
			if err := relFunc(); err != nil {
				reloadErrors = multierror.Append(reloadErrors, fmt.Errorf("error encountered reloading listener: %w", err))
			}
		}
	}

	if newConf != nil && c.worker != nil {
		c.worker.ParseAndStoreTags(newConf.Worker.Tags)
	}

	// Send a message that we reloaded. This prevents "guessing" sleep times
	// in tests.
	if c.reloadedCh != nil {
		select {
		case c.reloadedCh <- struct{}{}:
		default:
		}
	}

	return reloadErrors.ErrorOrNil()
}

func (c *Command) verifyKmsSetup() error {
	const op = "server.(Command).verifyKmsExists"
	rw := db.New(c.Database)

	ctx := context.Background()
	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms: %w", err)
	}
	if err := kmsCache.VerifyGlobalRoot(ctx); err != nil {
		return err
	}
	return nil
}
