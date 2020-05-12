package worker

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/config"
	"github.com/hashicorp/watchtower/internal/servers/worker"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Server

	ExtShutdownCh chan struct{}
	SighupCh      chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	cleanupGuard sync.Once

	Config *config.Config
	worker *worker.Worker

	flagConfig              string
	flagLogLevel            string
	flagLogFormat           string
	flagDev                 bool
	flagDevWorkerListenAddr string
	flagCombineLogs         bool
}

func (c *Command) Synopsis() string {
	return "Start a Watchtower worker"
}

func (c *Command) Help() string {
	helpText := `
Usage: watchtower worker [options]

  Start a worker with a configuration file:

      $ watchtower worker -config=/etc/watchtower/worker.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "config",
		Target: &c.flagConfig,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to a configuration file.",
	})

	f.StringVar(&base.StringVar{
		Name:       "log-level",
		Target:     &c.flagLogLevel,
		Default:    base.NotSetValue,
		EnvVar:     "WATCHTOWER_LOG_LEVEL",
		Completion: complete.PredictSet("trace", "debug", "info", "warn", "err"),
		Usage: "Log verbosity level. Supported values (in order of more detail to less) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"err\".",
	})

	f.StringVar(&base.StringVar{
		Name:       "log-format",
		Target:     &c.flagLogFormat,
		Default:    base.NotSetValue,
		Completion: complete.PredictSet("standard", "json"),
		Usage:      `Log format. Supported values are "standard" and "json".`,
	})

	f = set.NewFlagSet("Dev Options")

	f.BoolVar(&base.BoolVar{
		Name:   "dev",
		Target: &c.flagDev,
		Usage: "Enable development mode. As the name implies, do not run \"dev\" mode in " +
			"production.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-listen-address",
		Target: &c.flagDevWorkerListenAddr,
		EnvVar: "WATCHTOWER_DEV_WORKER_LISTEN_ADDRESS",
		Usage:  "Address to bind the worker to in \"dev\" mode.",
	})

	f.BoolVar(&base.BoolVar{
		Name:    "combine-logs",
		Target:  &c.flagCombineLogs,
		Default: false,
		Usage:   "If set, both startup information and logs will be sent to stdout. If not set (the default), startup information will go to stdout and logs will be sent to stderr.",
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
		return 1
	}

	base.StartMemProfiler(c.Logger)

	if err := c.SetupMetrics(c.UI, c.Config.Telemetry); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if err := c.SetupKMSes(c.UI, c.Config.SharedConfig, []string{"worker-auth"}); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.WorkerAuthKMS == nil {
		c.UI.Error("Worker Auth KMS not found after parsing KMS blocks")
		return 1
	}

	// If mlockall(2) isn't supported, show a warning. We disable this in dev
	// because it is quite scary to see when first using Watchtower. We also disable
	// this if the user has explicitly disabled mlock in configuration.
	if !c.flagDev && !c.Config.DisableMlock && !mlock.Supported() {
		c.UI.Warn(base.WrapAtLength(
			"WARNING! mlock is not supported on this system! An mlockall(2)-like " +
				"syscall to prevent memory from being swapped to disk is not " +
				"supported on this system. For better security, only run Watchtower on " +
				"systems where this call is supported. If you are running Watchtower" +
				"in a Docker container, provide the IPC_LOCK cap to the container."))
	}

	if err := c.SetupListeners(c.UI, c.Config.SharedConfig); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return 1
	}

	defer c.RunShutdownFuncs(c.UI)

	c.PrintInfo(c.UI, "worker")
	c.ReleaseLogGate()

	if err := c.Start(); err != nil {
		c.UI.Error(err.Error())
		return 1
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

	// Validation
	if !c.flagDev {
		if len(c.flagConfig) == 0 {
			c.UI.Error("Must supply a config file with -config")
			return 1
		}
		c.Config, err = config.LoadFile(c.flagConfig)
		if err != nil {
			c.UI.Error("Error parsing config: " + err.Error())
			return 1
		}

	} else {
		c.Config, err = config.DevWorker()
		if err != nil {
			c.UI.Error(fmt.Errorf("Error creating dev config: %s", err).Error())
			return 1
		}

		if c.flagDevWorkerListenAddr != "" {
			c.Config.Listeners[0].Address = c.flagDevWorkerListenAddr
		}
	}

	return 0
}

func (c *Command) Start() error {
	// Instantiate the wait group
	conf := &worker.Config{
		RawConfig: c.Config,
		Server:    c.Server,
	}

	// Initialize the core
	var err error
	c.worker, err = worker.New(conf)
	if err != nil {
		return fmt.Errorf("Error initializing worker: %w", err)
	}

	if err := c.worker.Start(); err != nil {
		retErr := fmt.Errorf("Error starting worker: %w", err)
		if err := c.worker.Shutdown(); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error with worker shutdown: %w", err)
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
			c.UI.Output("==> Watchtower worker shutdown triggered")

			if err := c.worker.Shutdown(); err != nil {
				c.UI.Error(fmt.Errorf("Error with worker shutdown: %w", err).Error())
			}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Watchtower worker reload triggered")

			// Check for new log level
			var level hclog.Level
			var err error
			var newConf *config.Config

			if c.flagConfig == "" {
				goto RUNRELOADFUNCS
			}

			newConf, err = config.LoadFile(c.flagConfig)
			if err != nil {
				c.Logger.Error("could not reload config", "path", c.flagConfig, "error", err)
				goto RUNRELOADFUNCS
			}

			// Ensure at least one config was found.
			if newConf == nil {
				c.Logger.Error("no config found at reload time")
				goto RUNRELOADFUNCS
			}

			// Commented out until we need this
			//c.worker.SetConfig(config)

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
				c.UI.Error(fmt.Errorf("Error(s) were encountered during worker reload: %w", err).Error())
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
