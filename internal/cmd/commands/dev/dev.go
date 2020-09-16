package dev

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/base"
	controllercmd "github.com/hashicorp/boundary/internal/cmd/commands/controller"
	workercmd "github.com/hashicorp/boundary/internal/cmd/commands/worker"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Server

	SighupCh      chan struct{}
	childSighupCh []chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	flagLogLevel                       string
	flagLogFormat                      string
	flagCombineLogs                    bool
	flagDevLoginName                   string
	flagDevPassword                    string
	flagDevAuthMethodId                string
	flagDevControllerAPIListenAddr     string
	flagDevControllerClusterListenAddr string
	flagDevSkipAuthMethodCreation      bool
	flagDevDisableDatabaseDestruction  bool
}

func (c *Command) Synopsis() string {
	return "Start a Boundary dev environment"
}

func (c *Command) Help() string {
	helpText := `
Usage: boundary dev [options]

  Start a dev environment: 

      $ boundary dev

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

	f.StringVar(&base.StringVar{
		Name:   "dev-auth-method-id",
		Target: &c.flagDevAuthMethodId,
		EnvVar: "WATCHTWER_DEV_AUTH_METHOD_ID",
		Usage: "Auto-created auth method ID. This only applies when running in \"dev\" " +
			"mode.",
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
		Usage:  "Address to bind to for controller \"api\" purpose.",
	})

	f.StringVar(&base.StringVar{
		Name:   "dev-cluster-listen-address",
		Target: &c.flagDevControllerClusterListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_CLUSTER_LISTEN_ADDRESS",
		Usage:  "Address to bind to for controller \"cluster\" purpose.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "dev-skip-auth-method-creation",
		Target: &c.flagDevSkipAuthMethodCreation,
		Usage:  "If set, an auth method will not be created as part of the dev instance. The recovery KMS will be needed to perform any actions.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "dev-disable-database-destruction",
		Target: &c.flagDevDisableDatabaseDestruction,
		Usage:  "If set, if a database is created automatically in Docker, it will not be removed when the dev server is shut down.",
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

	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	childShutdownCh := make(chan struct{})

	devConfig, err := config.DevCombined()
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating controller dev config: %w", err).Error())
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

	devConfig.PassthroughDirectory = c.FlagDevPassthroughDirectory

	for _, l := range devConfig.Listeners {
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

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, "", ""); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	base.StartMemProfiler(c.Logger)

	if err := c.SetupMetrics(c.UI, devConfig.Telemetry); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.FlagDevRecoveryKey != "" {
		devConfig.Controller.DevRecoveryKey = c.FlagDevRecoveryKey
	}
	if err := c.SetupKMSes(c.UI, devConfig); err != nil {
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
	c.InfoKeys = append(c.InfoKeys, "[Controller] AEAD Key Bytes")
	c.Info["[Controller] AEAD Key Bytes"] = devConfig.Controller.DevControllerKey
	c.InfoKeys = append(c.InfoKeys, "[Worker-Auth] AEAD Key Bytes")
	c.Info["[Worker-Auth] AEAD Key Bytes"] = devConfig.Controller.DevWorkerAuthKey
	c.InfoKeys = append(c.InfoKeys, "[Recovery] AEAD Key Bytes")
	c.Info["[Recovery] AEAD Key Bytes"] = devConfig.Controller.DevRecoveryKey

	// Initialize the listeners
	if err := c.SetupListeners(c.UI, devConfig.SharedConfig, []string{"api", "cluster", "proxy"}); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(devConfig.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return 1
	}

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

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
	if !c.flagDevDisableDatabaseDestruction {
		c.ShutdownFuncs = append(c.ShutdownFuncs, c.DestroyDevDatabase)
	}

	c.PrintInfo(c.UI, "dev mode")
	c.ReleaseLogGate()

	// Instantiate the wait group
	shutdownWg := &sync.WaitGroup{}
	shutdownWg.Add(2)
	controllerSighupCh := make(chan struct{})
	c.childSighupCh = append(c.childSighupCh, controllerSighupCh)

	devController := &controllercmd.Command{
		Server:        c.Server,
		ExtShutdownCh: childShutdownCh,
		SighupCh:      controllerSighupCh,
		Config:        devConfig,
	}
	if err := devController.Start(); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	workerSighupCh := make(chan struct{})
	c.childSighupCh = append(c.childSighupCh, workerSighupCh)
	devWorker := &workercmd.Command{
		Server:        c.Server,
		ExtShutdownCh: childShutdownCh,
		SighupCh:      workerSighupCh,
		Config:        devConfig,
	}
	if err := devWorker.Start(); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	go func() {
		defer shutdownWg.Done()
		devController.WaitForInterrupt()
	}()
	go func() {
		defer shutdownWg.Done()
		devWorker.WaitForInterrupt()
	}()

	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> Boundary dev environment shutdown triggered")

			childShutdownCh <- struct{}{}
			childShutdownCh <- struct{}{}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> Boundary dev environment reload triggered")
			for _, v := range c.childSighupCh {
				v <- struct{}{}
			}

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			c.Logger.Info("goroutine trace", "stack", string(buf[:n]))
		}
	}

	shutdownWg.Wait()

	return 0
}
