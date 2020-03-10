package dev

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	controllercmd "github.com/hashicorp/watchtower/internal/cmd/commands/controller"
	controllerconfig "github.com/hashicorp/watchtower/internal/cmd/commands/controller/config"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

var memProfilerEnabled = false

type Command struct {
	*base.Command
	*base.Server

	ShutdownCh    chan struct{}
	SighupCh      chan struct{}
	childSighupCh []chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	cleanupGuard sync.Once

	flagConfig                  string
	flagLogLevel                string
	flagLogFormat               string
	flagDev                     bool
	flagDevAdminToken           string
	flagDevControllerListenAddr string
	flagCombineLogs             bool
}

func (c *Command) Synopsis() string {
	return "Start a Watchtower dev environment"
}

func (c *Command) Help() string {
	helpText := `
Usage: watchtower dev [options]

  Start a dev environment: 

      $ watchtower dev

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

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

	f.StringVar(&base.StringVar{
		Name:    "dev-admin-token",
		Target:  &c.flagDevAdminToken,
		Default: "",
		EnvVar:  "WATCHTWER_DEV_ADMIN_TOKEN",
		Usage: "Initial admin token. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.StringVar(&base.StringVar{
		Name:    "dev-listen-address",
		Target:  &c.flagDevControllerListenAddr,
		Default: "127.0.0.1:9200",
		EnvVar:  "WATCHTOWER_DEV_LISTEN_ADDRESS",
		Usage:   "Address to bind against.",
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
	c.Server = base.NewServer()
	c.CombineLogs = c.flagCombineLogs

	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	childShutdownCh := make(chan struct{})

	devControllerConfig, err := controllerconfig.Dev()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating controller dev config: %s", err))
		return 1
	}

	if memProfilerEnabled {
		c.startMemProfiler()
	}

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, "", ""); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if err := c.SetupMetrics(c.UI, devControllerConfig.Telemetry); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if err := c.SetupKMSes(c.UI, devControllerConfig.SharedConfig, 2); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Initialize the listeners
	if err := c.SetupListeners(c.UI, devControllerConfig.SharedConfig); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(devControllerConfig.PidFile); err != nil {
		c.UI.Error(fmt.Sprintf("Error storing PID: %w", err))
		return 1
	}

	/*
		// If we're in Dev mode, then initialize the core
		if c.flagDev && !c.flagDevSkipInit {
			init, err := c.enableDev(core, coreConfig)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error initializing Dev mode: %w", err))
				return 1
			}

			// Print the big dev mode warning!
			c.UI.Warn(base.WrapAtLength(
				"WARNING! dev mode is enabled! In this mode, Watchtower runs entirely " +
					"in-memory and all state is lost upon shutdown."))
			c.UI.Warn("")
			c.UI.Warn("You may need to set the following environment variable:")
			c.UI.Warn("")

			endpointURL := "http://" + config.Listeners[0].Config["address"].(string)
			if runtime.GOOS == "windows" {
				c.UI.Warn("PowerShell:")
				c.UI.Warn(fmt.Sprintf("    $env:WATCHTOWER_ADDR=\"%s\"", endpointURL))
				c.UI.Warn("cmd.exe:")
				c.UI.Warn(fmt.Sprintf("    set WATCHTOWER_ADDR=%s", endpointURL))
			} else {
				c.UI.Warn(fmt.Sprintf("    $ export VAULT_ADDR='%s'", endpointURL))
			}

			c.UI.Warn(fmt.Sprintf("Root Token: %s", init.RootToken))

			c.UI.Warn("")
			c.UI.Warn(base.WrapAtLength(
				"Development mode should NOT be used in production installations!"))
			c.UI.Warn("")
		}
	*/

	defer c.RunShutdownFuncs(c.UI)

	if err := c.CreateDevDatabase(); err != nil {
		c.UI.Error(fmt.Sprintf("Error creating dev database container: %s", err.Error()))
		return 1
	}
	c.ShutdownFuncs = append(c.ShutdownFuncs, c.DestroyDevDatabase)

	c.PrintInfo(c.UI, "dev mode")
	c.ReleaseLogGate()

	// Instantiate the wait group
	shutdownWg := &sync.WaitGroup{}
	shutdownWg.Add(1)
	controllerSighupCh := make(chan struct{})
	c.childSighupCh = append(c.childSighupCh, controllerSighupCh)
	go func() {
		defer shutdownWg.Done()
		devController := &controllercmd.Command{
			Command:    c.Command,
			Server:     c.Server,
			ShutdownCh: childShutdownCh,
			SighupCh:   controllerSighupCh,
			Config:     devControllerConfig,
		}
		devController.Start()
	}()

	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> Watchtower dev environment shutdown triggered")

			close(childShutdownCh)

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Watchtower dev environment reload triggered")
			for _, v := range c.childSighupCh {
				v <- struct{}{}
			}

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			c.Logger.Info("goroutine trace", "stack", string(buf[:n]))
		}
	}

	// Wait for dependent goroutines to complete
	shutdownWg.Wait()

	return 0
}
