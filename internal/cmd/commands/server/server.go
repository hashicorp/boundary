package server

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Server

	ExtShutdownCh chan struct{}
	SighupCh      chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	Config     *config.Config
	controller *controller.Controller
	worker     *worker.Worker

	configWrapper wrapping.Wrapper

	flagConfig      string
	flagConfigKms   string
	flagLogLevel    string
	flagLogFormat   string
	flagCombineLogs bool
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

	if c.configWrapper != nil {
		defer func() {
			if err := c.configWrapper.Finalize(c.Context); err != nil {
				c.UI.Warn(fmt.Errorf("Error finalizing config kms: %w", err).Error())
			}
		}()
	}

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	base.StartMemProfiler(c.Logger)

	if err := c.SetupMetrics(c.UI, c.Config.Telemetry); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if err := c.SetupKMSes(c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.Config.Controller != nil {
		if c.RootKms == nil {
			c.UI.Error("Root KMS not found after parsing KMS blocks")
			return 1
		}
	}
	if c.WorkerAuthKms == nil {
		c.UI.Error("Worker Auth KMS not found after parsing KMS blocks")
		return 1
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
			return 1

		case 1:
			purpose := lnConfig.Purpose[0]
			switch purpose {
			case "cluster":
				clusterAddr = lnConfig.Address
				if clusterAddr == "" {
					clusterAddr = "127.0.0.1:9201"
				}
			case "api":
				foundApi = true
			case "proxy":
				foundProxy = true
			default:
				c.UI.Error(fmt.Sprintf("Unknown listener purpose %q", lnConfig.Purpose[0]))
				return 1
			}

		default:
			c.UI.Error("Specifying a listener with more than one purpose is not supported")
			return 1
		}
	}
	if c.Config.Controller != nil {
		if !foundApi {
			c.UI.Error(`Config activates controller but no listener with "api" purpose found`)
			return 1
		}
		if clusterAddr == "" {
			c.UI.Error(`Config activates controller but no listener with "cluster" purpose found`)
			return 1
		}
	}
	if c.Config.Worker != nil {
		if !foundProxy {
			c.UI.Error(`Config activates worker but no listener with "proxy" purpose found`)
			return 1
		}
		if c.Config.Controller != nil {
			switch len(c.Config.Worker.Controllers) {
			case 0:
				c.Config.Worker.Controllers = []string{clusterAddr}
			case 1:
				if c.Config.Worker.Controllers[0] == clusterAddr {
					break
				}
				// Best effort see if it's a domain name and if not assume it must match
				host, _, err := net.SplitHostPort(c.Config.Worker.Controllers[0])
				if err != nil && strings.Contains(err.Error(), "missing port in address") {
					err = nil
					host = c.Config.Worker.Controllers[0]
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
				c.UI.Error(`When running a combined controller and worker, it's invalid to specify a "controllers" key in the worker block with any value other than the controller cluster address/port when using IPs rather than DNS names`)
				return 1
			}
		}
		for _, controller := range c.Config.Worker.Controllers {
			host, _, err := net.SplitHostPort(controller)
			if err != nil {
				if strings.Contains(err.Error(), "missing port in address") {
					host = controller
				} else {
					c.UI.Error(fmt.Errorf("Invalid controller address %q: %w", controller, err).Error())
					return 1
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
					c.UI.Error(fmt.Sprintf("Controller address %q is invalid: cannot be %s address", controller, errMsg))
					return 1
				}
			}
		}
	}
	if err := c.SetupListeners(c.UI, c.Config.SharedConfig, []string{"api", "cluster", "proxy"}); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.Config.Worker != nil {
		if err := c.SetupWorkerPublicAddress(c.Config, ""); err != nil {
			c.UI.Error(err.Error())
			return 1
		}
		c.InfoKeys = append(c.InfoKeys, "public addr")
		c.Info["public addr"] = c.Config.Worker.PublicAddr
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
						return 1
					}
				}
				ip := net.ParseIP(host)
				if ip != nil {
					if ip.IsUnspecified() && c.Config.Controller.PublicClusterAddr == "" {
						c.UI.Error(fmt.Sprintf("When %q listener has an unspecified address, %q must be set", "cluster", "public_cluster_addr"))
						return 1
					}
				}
			}
		}

		if err := c.SetupControllerPublicClusterAddress(c.Config, ""); err != nil {
			c.UI.Error(err.Error())
			return 1
		}
		c.InfoKeys = append(c.InfoKeys, "public cluster addr")
		c.Info["public cluster addr"] = c.Config.Controller.PublicClusterAddr
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return 1
	}

	if c.Config.Controller != nil {
		if c.Config.Controller.Database == nil || c.Config.Controller.Database.Url == "" {
			c.UI.Error(`"url" not specified in "controller.database" config block"`)
			return 1
		}
		var err error
		c.DatabaseUrl, err = config.ParseAddress(c.Config.Controller.Database.Url)
		if err != nil && err != config.ErrNotAUrl {
			c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
			return 1
		}
		if err := c.ConnectToDatabase("postgres"); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return 1
		}

		sMan, err := schema.NewManager(c.Context, "postgres", c.Database.DB())
		if err != nil {
			c.UI.Error(fmt.Errorf("Can't get schema manager: %w.", err).Error())
			return 1
		}
		// This is an advisory locks on the DB which is released when the db session ends.
		if err := sMan.SharedLock(c.Context); err != nil {
			c.UI.Error(fmt.Errorf("Unable to gain shared access to the database: %w", err).Error())
			return 1
		}
		defer func() {
			if err := sMan.SharedUnlock(c.Context); err != nil {
				c.UI.Error(fmt.Errorf("Unable to release shared lock to the database: %w", err).Error())
			}
		}()
		ckState, err := sMan.CurrentState(c.Context)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error checking schema state: %w", err).Error())
			return 1
		}
		if ckState.Dirty {
			c.UI.Error(base.WrapAtLength("Database is in a bad state. Please revert the database into the last known good state."))
			return 1
		}
		if ckState.BinarySchemaVersion > ckState.DatabaseSchemaVersion {
			c.UI.Error(base.WrapAtLength("Database schema must be updated to use this version. Run 'boundary database migrate' to update the database."))
			return 1
		}
		if ckState.BinarySchemaVersion < ckState.DatabaseSchemaVersion {
			c.UI.Error(base.WrapAtLength(fmt.Sprintf("Newer schema version (%d) "+
				"than this binary expects. Please use a newer version of the boundary "+
				"binary.", ckState.DatabaseSchemaVersion)))
			return 1
		}
		if err := c.verifyKmsSetup(); err != nil {
			c.UI.Error(base.WrapAtLength("Database is in a bad state. Please revert the database into the last known good state."))
			return 1
		}
	}

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	c.PrintInfo(c.UI)
	c.ReleaseLogGate()

	if c.Config.Controller != nil {
		if err := c.StartController(); err != nil {
			c.UI.Error(err.Error())
			return 1
		}
	}

	if c.Config.Worker != nil {
		if err := c.StartWorker(); err != nil {
			c.UI.Error(err.Error())
			if err := c.controller.Shutdown(false); err != nil {
				c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
			}
			return 1
		}
	}

	return c.WaitForInterrupt()
}

func (c *Command) ParseFlagsAndConfig(args []string) int {
	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	wrapperPath := c.flagConfig
	if c.flagConfigKms != "" {
		wrapperPath = c.flagConfigKms
	}
	wrapper, err := wrapper.GetWrapperFromPath(wrapperPath, "config")
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if wrapper != nil {
		c.configWrapper = wrapper
		if err := wrapper.Init(c.Context); err != nil {
			c.UI.Error(fmt.Errorf("Could not initialize kms: %w", err).Error())
			return 1
		}
	}

	if len(c.flagConfig) == 0 {
		c.UI.Error("Must specify a config file using -config")
		return 1
	}

	c.Config, err = config.LoadFile(c.flagConfig, wrapper)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return 1
	}

	if c.Config.Controller == nil && c.Config.Worker == nil {
		c.UI.Error("Neither worker nor controller specified in configuration file.")
		return 1
	}
	if c.Config.Controller != nil && c.Config.Controller.Name == "" {
		c.UI.Error("Controller has no name set. It must be the unique name of this instance.")
		return 1
	}
	if c.Config.Worker != nil && c.Config.Worker.Name == "" {
		c.UI.Error("Worker has no name set. It must be the unique name of this instance.")
		return 1
	}

	return 0
}

func (c *Command) StartController() error {
	conf := &controller.Config{
		RawConfig: c.Config,
		Server:    c.Server,
	}

	var err error
	c.controller, err = controller.New(conf)
	if err != nil {
		return fmt.Errorf("Error initializing controller: %w", err)
	}

	if err := c.controller.Start(); err != nil {
		retErr := fmt.Errorf("Error starting controller: %w", err)
		if err := c.controller.Shutdown(false); err != nil {
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
		if err := c.worker.Shutdown(false); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error shutting down worker: %w", err)
		}
		return retErr
	}

	return nil
}

func (c *Command) WaitForInterrupt() int {
	// Wait for shutdown
	shutdownTriggered := false

	shutdownCh := c.ShutdownCh
	if c.ExtShutdownCh != nil {
		shutdownCh = c.ExtShutdownCh
	}

	for !shutdownTriggered {
		select {
		case <-shutdownCh:
			c.UI.Output("==> Boundary server shutdown triggered")

			if c.Config.Worker != nil {
				if err := c.worker.Shutdown(false); err != nil {
					c.UI.Error(fmt.Errorf("Error shutting down worker: %w", err).Error())
				}
			}

			if c.Config.Controller != nil {
				if err := c.controller.Shutdown(c.Config.Worker != nil); err != nil {
					c.UI.Error(fmt.Errorf("Error shutting down controller: %w", err).Error())
				}
			}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Boundary server reload triggered")

			// Check for new log level
			var level hclog.Level
			var err error
			var newConf *config.Config

			if c.flagConfig == "" {
				goto RUNRELOADFUNCS
			}

			newConf, err = config.LoadFile(c.flagConfig, c.configWrapper)
			if err != nil {
				c.Logger.Error("could not reload config", "path", c.flagConfig, "error", err)
				goto RUNRELOADFUNCS
			}

			// Ensure at least one config was found.
			if newConf == nil {
				c.Logger.Error("no config found at reload time")
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
					c.Logger.Error("unknown log level found on reload", "level", newConf.LogLevel)
					goto RUNRELOADFUNCS
				}
				c.Logger.SetLevel(level)
			}

		RUNRELOADFUNCS:
			if err := c.Reload(); err != nil {
				c.UI.Error(fmt.Errorf("Error(s) were encountered during server reload: %w", err).Error())
			}

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			c.Logger.Info("goroutine trace", "stack", string(buf[:n]))
		}
	}

	return 0
}

func (c *Command) Reload() error {
	c.ReloadFuncsLock.RLock()
	defer c.ReloadFuncsLock.RUnlock()

	var reloadErrors *multierror.Error

	for k, relFuncs := range c.ReloadFuncs {
		switch {
		case strings.HasPrefix(k, "listener|"):
			for _, relFunc := range relFuncs {
				if relFunc != nil {
					if err := relFunc(); err != nil {
						reloadErrors = multierror.Append(reloadErrors, fmt.Errorf("error encountered reloading listener: %w", err))
					}
				}
			}
		}
	}

	// Send a message that we reloaded. This prevents "guessing" sleep times
	// in tests.
	select {
	case c.ReloadedCh <- struct{}{}:
	default:
	}

	return reloadErrors.ErrorOrNil()
}

func (c *Command) verifyKmsSetup() error {
	const op = "server.(Command).verifyKmsExists"
	rw := db.New(c.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms repository: %w", err)
	}
	rks, err := kmsRepo.ListRootKeys(c.Context, kms.WithLimit(1))
	if err != nil {
		return err
	}
	for _, rk := range rks {
		if rk.GetScopeId() == scope.Global.String() {
			return nil
		}
	}
	return errors.New(errors.MigrationIntegrity, op, "can't find global scoped root key")
}
