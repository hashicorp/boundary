package controller

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/helper/mlock"
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

	Config     *config.Config
	controller *controller.Controller

	configWrapper wrapping.Wrapper

	flagConfig                         string
	flagConfigKms                      string
	flagLogLevel                       string
	flagLogFormat                      string
	flagCombineLogs                    bool
	flagDev                            bool
	flagDevLoginName                   string
	flagDevPassword                    string
	flagDevControllerAPIListenAddr     string
	flagDevControllerClusterListenAddr string
	flagDevAuthMethodId                string
	flagDevSkipAuthMethodCreation      bool
}

func (c *Command) Synopsis() string {
	return "Start a Boundary controller"
}

func (c *Command) Help() string {
	helpText := `
Usage: boundary controller [options]

  Start a controller with a configuration file:

      $ boundary controller -config=/etc/boundary/controller.hcl

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
		Default:    base.NotSetValue,
		EnvVar:     "BOUNDARY_LOG_LEVEL",
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
		Name:   "dev-auth-method-id",
		Target: &c.flagDevAuthMethodId,
		EnvVar: "WATCHTWER_DEV_AUTH_METHOD_ID",
		Usage: "Auto-created auth method ID. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "dev-skip-auth-method-creation",
		Target: &c.flagDevSkipAuthMethodCreation,
		Usage:  "If set, an auth method will not be created as part of the dev instance. The recovery KMS will be needed to perform any actions.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-password",
		Target: &c.flagDevPassword,
		EnvVar: "WATCHTWER_DEV_PASSWORD",
		Usage: "Initial admin password. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-login-name",
		Target: &c.flagDevLoginName,
		EnvVar: "WATCHTWER_DEV_LOGIN_NAME",
		Usage: "Initial admin login name. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-api-listen-address",
		Target: &c.flagDevControllerAPIListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_API_LISTEN_ADDRESS",
		Usage:  "Address to bind the controller to in \"dev\" mode for \"api\" purpose.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-cluster-listen-address",
		Target: &c.flagDevControllerClusterListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_CLUSTER_LISTEN_ADDRESS",
		Usage:  "Address to bind the controller to in \"dev\" mode for \"cluster\" purpose.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "combine-logs",
		Target: &c.flagCombineLogs,
		Usage:  "If set, both startup information and logs will be sent to stdout. If not set (the default), startup information will go to stdout and logs will be sent to stderr.",
	})

	base.DevOnlyControllerFlags(c.Command, f)

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

	if c.FlagDevRecoveryKey != "" {
		c.Config.Controller.DevRecoveryKey = c.FlagDevRecoveryKey
	}
	if err := c.SetupKMSes(c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if c.RootKms == nil {
		c.UI.Error("Controller KMS not found after parsing KMS blocks")
		return 1
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
	if !c.flagDev && !c.Config.DisableMlock && !mlock.Supported() {
		c.UI.Warn(base.WrapAtLength(
			"WARNING! mlock is not supported on this system! An mlockall(2)-like " +
				"syscall to prevent memory from being swapped to disk is not " +
				"supported on this system. For better security, only run Boundary on " +
				"systems where this call is supported. If you are running Boundary" +
				"in a Docker container, provide the IPC_LOCK cap to the container."))
	}

	// Perform controller-specific listener checks here before setup
	var foundCluster bool
	var foundAPI bool
	for _, lnConfig := range c.Config.Listeners {
		switch len(lnConfig.Purpose) {
		case 1:
			switch lnConfig.Purpose[0] {
			case "cluster":
				foundCluster = true
			case "api":
				foundAPI = true
			case "proxy":
				// Do nothing, in a dev mode we might see it here
			default:
				c.UI.Error(fmt.Sprintf("Unknown listener purpose %q", lnConfig.Purpose[0]))
				return 1
			}

		case 0:
			lnConfig.Purpose = []string{"api", "cluster"}
			fallthrough

		case 2:
			if !strutil.StrListContains(lnConfig.Purpose, "api") || !strutil.StrListContains(lnConfig.Purpose, "cluster") {
				c.UI.Error(fmt.Sprintf("Invalid listener purpose set: %v", lnConfig.Purpose))
				return 1
			}
			if lnConfig.TLSDisable {
				c.UI.Error(fmt.Sprintf("TLS cannot be disabled on listener when serving both %q and %q purposes", "api", "cluster"))
				return 1
			}
			foundAPI = true
			foundCluster = true
		}
	}
	if foundAPI && !foundCluster {
		c.UI.Error("No listener marked for cluster purpose found, but listener explicitly marked for api was found")
		return 1
	}
	if err := c.SetupListeners(c.UI, c.Config.SharedConfig, []string{"api", "cluster"}); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return 1
	}

	if c.flagDev {
		var opts []base.Option
		if c.flagDevSkipAuthMethodCreation {
			opts = append(opts, base.WithSkipAuthMethodCreation())
			switch {
			case c.flagDevAuthMethodId != "",
				c.flagDevLoginName != "",
				c.flagDevPassword != "":
				c.UI.Warn("-dev-skip-auth-method-creation set, skipping any auth-method related flags")
			}
		}
		if err := c.CreateDevDatabase("postgres", opts...); err != nil {
			c.UI.Error(fmt.Errorf("Error creating dev database container: %w", err).Error())
			return 1
		}
		c.ShutdownFuncs = append(c.ShutdownFuncs, c.DestroyDevDatabase)
	} else {
		if c.Config.Database == nil || c.Config.Database.Url == "" {
			c.UI.Error(`"url" not specified in "database" config block"`)
			return 1
		}
		dbaseUrl, err := config.ParseAddress(c.Config.Database.Url)
		if err != nil && err != config.ErrNotAUrl {
			c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
			return 1
		}
		c.DatabaseUrl = strings.TrimSpace(dbaseUrl)
		if err := db.InitStore("postgres", nil, c.DatabaseUrl); err != nil {
			c.UI.Error(fmt.Errorf("Error running database migrations: %w", err).Error())
			return 1
		}
		if err := c.ConnectToDatabase("postgres"); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return 1
		}
	}

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	c.PrintInfo(c.UI, "controller")
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

	// Validation
	if !c.flagDev {
		switch {
		case len(c.flagConfig) == 0:
			c.UI.Error("Must specify a config file using -config")
			return 1
		case c.flagDevPassword != "":
			c.UI.Warn(base.WrapAtLength(
				"You cannot specify a custom admin password outside of \"dev\" mode. " +
					"Your request has been ignored."))
			c.flagDevPassword = ""
		case c.flagDevLoginName != "":
			c.UI.Warn(base.WrapAtLength(
				"You cannot specify a custom admin login name outside of \"dev\" mode. " +
					"Your request has been ignored."))
			c.flagDevLoginName = ""
		}

		c.Config, err = config.LoadFile(c.flagConfig, wrapper)
		if err != nil {
			c.UI.Error("Error parsing config: " + err.Error())
			return 1
		}

	} else {
		if len(c.flagConfig) == 0 {
			c.Config, err = config.DevController()
		} else {
			c.Config, err = config.LoadFile(c.flagConfig, wrapper)
		}
		if err != nil {
			c.UI.Error(fmt.Errorf("Error creating dev config: %w", err).Error())
			return 1
		}

		if c.flagDevAuthMethodId != "" {
			prefix := password.AuthMethodPrefix + "_"
			if !strings.HasPrefix(c.flagDevAuthMethodId, prefix) {
				c.UI.Error(fmt.Sprintf("Invalid dev auth method ID, must start with %q", prefix))
				return 1
			}
			if len(c.flagDevAuthMethodId) != 15 {
				c.UI.Error(fmt.Sprintf("Invalid dev auth method ID, must be 10 base62 characters after %q", prefix))
				return 1
			}
			c.DevAuthMethodId = c.flagDevAuthMethodId
		}
		if c.flagDevLoginName != "" {
			c.DevLoginName = c.flagDevLoginName
		}
		if c.flagDevPassword != "" {
			c.DevPassword = c.flagDevPassword
		}

		c.Config.PassthroughDirectory = c.FlagDevPassthroughDirectory

		for _, l := range c.Config.Listeners {
			if len(l.Purpose) != 1 {
				continue
			}
			switch l.Purpose[0] {
			case "api":
				if c.flagDevControllerAPIListenAddr != "" {
					l.Address = c.flagDevControllerAPIListenAddr
				}

			case "cluster":
				if c.flagDevControllerClusterListenAddr != "" {
					l.Address = c.flagDevControllerClusterListenAddr
				}
			}
		}
	}

	return 0
}

func (c *Command) Start() error {
	// Instantiate the wait group
	conf := &controller.Config{
		RawConfig: c.Config,
		Server:    c.Server,
	}

	// Initialize the core
	var err error
	c.controller, err = controller.New(conf)
	if err != nil {
		return fmt.Errorf("Error initializing controller: %w", err)
	}

	if err := c.controller.Start(); err != nil {
		retErr := fmt.Errorf("Error starting controller: %w", err)
		if err := c.controller.Shutdown(false); err != nil {
			c.UI.Error(retErr.Error())
			retErr = fmt.Errorf("Error with controller shutdown: %w", err)
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
			c.UI.Output("==> Boundary controller shutdown triggered")

			if err := c.controller.Shutdown(false); err != nil {
				c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
			}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Boundary controller reload triggered")

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
				c.UI.Error(fmt.Errorf("Error(s) were encountered during controller reload: %w", err).Error())
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
