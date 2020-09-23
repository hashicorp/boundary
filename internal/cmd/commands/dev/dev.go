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
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
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

	flagLogLevel                    string
	flagLogFormat                   string
	flagCombineLogs                 bool
	flagLoginName                   string
	flagPassword                    string
	flagIdSuffix                    string
	flagControllerAPIListenAddr     string
	flagControllerClusterListenAddr string
	flagWorkerProxyListenAddr       string
	flagWorkerPublicAddr            string
	flagPassthroughDirectory        string
	flagRecoveryKey                 string
	flagDisableDatabaseDestruction  bool
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

	f.StringVar(&base.StringVar{
		Name:   "id-suffix",
		Target: &c.flagIdSuffix,
		EnvVar: "BOUNDARY_DEV_ID_SUFFIX",
		Usage:  `If set, auto-created resources will use this value for their identifier (along with their resource-specific prefix). Must be 10 alphanumeric characters. As an example, if this is set to "1234567890", the generated password auth method ID will be "ampw_1234567890", the generated TCP target ID will be "ttcp_1234567890", and so on.`,
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		EnvVar: "BOUNDARY_DEV_PASSWORD",
		Usage:  "Initial login password.",
	})

	f.StringVar(&base.StringVar{
		Name:   "login-name",
		Target: &c.flagLoginName,
		EnvVar: "BOUNDARY_DEV_LOGIN_NAME",
		Usage:  "Initial admin login name.",
	})

	f.StringVar(&base.StringVar{
		Name:   "api-listen-address",
		Target: &c.flagControllerAPIListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_API_LISTEN_ADDRESS",
		Usage:  "Address to bind to for controller \"api\" purpose.",
	})

	f.StringVar(&base.StringVar{
		Name:   "cluster-listen-address",
		Target: &c.flagControllerClusterListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_CLUSTER_LISTEN_ADDRESS",
		Usage:  "Address to bind to for controller \"cluster\" purpose.",
	})

	f.StringVar(&base.StringVar{
		Name:   "proxy-listen-address",
		Target: &c.flagWorkerProxyListenAddr,
		EnvVar: "BOUNDARY_DEV_WORKER_PROXY_LISTEN_ADDRESS",
		Usage:  "Address to bind to for worker \"proxy\" purpose.",
	})

	f.StringVar(&base.StringVar{
		Name:   "worker-public-address",
		Target: &c.flagWorkerPublicAddr,
		EnvVar: "BOUNDARY_DEV_WORKER_PUBLIC_ADDRESS",
		Usage:  "Public address at which the worker is reachable for session proxying.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "disable-database-destruction",
		Target: &c.flagDisableDatabaseDestruction,
		Usage:  "If set, if a database is created automatically in Docker, it will not be removed when the dev server is shut down.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "combine-logs",
		Target: &c.flagCombineLogs,
		Usage:  "If set, both startup information and logs will be sent to stdout. If not set (the default), startup information will go to stdout and logs will be sent to stderr.",
	})

	f.StringVar(&base.StringVar{
		Name:   "passthrough-directory",
		Target: &c.flagPassthroughDirectory,
		EnvVar: "BOUNDARY_DEV_PASSTHROUGH_DIRECTORY",
		Usage:  "Enables a passthrough directory in the webserver at /",
	})

	f.StringVar(&base.StringVar{
		Name:   "recovery-key",
		Target: &c.flagRecoveryKey,
		EnvVar: "BOUNDARY_DEV_RECOVERY_KEY",
		Usage:  "Specifies the base64'd 256-bit AES key to use for recovery operations",
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
	if c.flagIdSuffix != "" {
		if len(c.flagIdSuffix) != 10 {
			c.UI.Error("Invalid ID suffix, must be exactly 10 characters")
			return 1
		}
		if !handlers.ValidId("abc", "abc_"+c.flagIdSuffix) {
			c.UI.Error("Invalid ID suffix, must be in the set A-Za-z0-9")
			return 1
		}
		c.DevAuthMethodId = fmt.Sprintf("%s_%s", password.AuthMethodPrefix, c.flagIdSuffix)
	}
	if c.flagLoginName != "" {
		c.DevLoginName = c.flagLoginName
	}
	if c.flagPassword != "" {
		c.DevPassword = c.flagPassword
	}

	devConfig.PassthroughDirectory = c.FlagDevPassthroughDirectory

	for _, l := range devConfig.Listeners {
		if len(l.Purpose) != 1 {
			continue
		}
		switch l.Purpose[0] {
		case "api":
			if c.flagControllerAPIListenAddr != "" {
				l.Address = c.flagControllerAPIListenAddr
			}

		case "cluster":
			if c.flagControllerClusterListenAddr != "" {
				l.Address = c.flagControllerClusterListenAddr
			}

		case "proxy":
			if c.flagWorkerProxyListenAddr != "" {
				l.Address = c.flagWorkerProxyListenAddr
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

	if err := c.SetupWorkerPublicAddress(devConfig, c.flagWorkerPublicAddr); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	c.InfoKeys = append(c.InfoKeys, "worker public addr")
	c.Info["worker public addr"] = devConfig.Worker.PublicAddr

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
	if err := c.CreateDevDatabase("postgres", opts...); err != nil {
		c.UI.Error(fmt.Errorf("Error creating dev database container: %w", err).Error())
		return 1
	}
	if !c.flagDisableDatabaseDestruction {
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
