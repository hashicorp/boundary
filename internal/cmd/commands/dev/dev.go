package dev

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Server

	UI         cli.Ui
	ShutdownCh chan struct{}

	SighupCh      chan struct{}
	childSighupCh []chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	Config     *config.Config
	controller *controller.Controller
	worker     *worker.Worker

	flagLogLevel                     string
	flagLogFormat                    string
	flagCombineLogs                  bool
	flagLoginName                    string
	flagPassword                     string
	flagUnprivilegedLoginName        string
	flagUnprivilegedPassword         string
	flagIdSuffix                     string
	flagHostAddress                  string
	flagTargetDefaultPort            int
	flagTargetSessionMaxSeconds      int
	flagTargetSessionConnectionLimit int
	flagControllerAPIListenAddr      string
	flagControllerClusterListenAddr  string
	flagControllerPublicClusterAddr  string
	flagWorkerProxyListenAddr        string
	flagWorkerPublicAddr             string
	flagPassthroughDirectory         string
	flagRecoveryKey                  string
	flagDatabaseUrl                  string
	flagDatabaseImage                string
	flagDisableDatabaseDestruction   bool
}

func NewCommand(server base.Server, ui cli.Ui) *Command {
	ret := &Command{
		Server:          &server,
		UI:              ui,
		flagCombineLogs: true,
	}

	return ret
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

	f.StringVar(&base.StringVar{
		Name:    "id-suffix",
		Target:  &c.flagIdSuffix,
		Default: "1234567890",
		EnvVar:  "BOUNDARY_DEV_ID_SUFFIX",
		Usage:   `If set, auto-created resources will use this value for their identifier (along with their resource-specific prefix). Must be 10 alphanumeric characters. As an example, if this is set to "1234567890", the generated password auth method ID will be "ampw_1234567890", the generated TCP target ID will be "ttcp_1234567890", and so on.`,
	})

	f.StringVar(&base.StringVar{
		Name:    "password",
		Target:  &c.flagPassword,
		Default: "password",
		EnvVar:  "BOUNDARY_DEV_PASSWORD",
		Usage:   "Initial admin login password. If set to the empty string, one will be autogenerated.",
	})

	f.StringVar(&base.StringVar{
		Name:    "login-name",
		Target:  &c.flagLoginName,
		Default: "admin",
		EnvVar:  "BOUNDARY_DEV_LOGIN_NAME",
		Usage:   "Initial admin login name. If set to the empty string, one will be autogenerated.",
	})

	f.StringVar(&base.StringVar{
		Name:    "unprivileged-password",
		Target:  &c.flagUnprivilegedPassword,
		Default: "password",
		EnvVar:  "BOUNDARY_DEV_UNPRIVILEGED_PASSWORD",
		Usage:   "Initial unprivileged user login password. If set to the empty string, one will be autogenerated.",
	})

	f.StringVar(&base.StringVar{
		Name:    "unprivileged-login-name",
		Target:  &c.flagUnprivilegedLoginName,
		Default: "user",
		EnvVar:  "BOUNDARY_DEV_UNPRIVILEGED_LOGIN_NAME",
		Usage:   "Initial unprivileged user name. If set to the empty string, one will be autogenerated.",
	})

	f.StringVar(&base.StringVar{
		Name:   "api-listen-address",
		Target: &c.flagControllerAPIListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_API_LISTEN_ADDRESS",
		Usage:  "Address to bind to for controller \"api\" purpose. If this begins with a forward slash, it will be assumed to be a Unix domain socket path.",
	})

	f.StringVar(&base.StringVar{
		Name:    "host-address",
		Default: "localhost",
		Target:  &c.flagHostAddress,
		EnvVar:  "BOUNDARY_DEV_HOST_ADDRESS",
		Usage:   "Address to use for the default host that is created. Must be a bare host or IP address, no port.",
	})

	f.IntVar(&base.IntVar{
		Name:    "target-default-port",
		Default: 22,
		Target:  &c.flagTargetDefaultPort,
		EnvVar:  "BOUNDARY_DEV_TARGET_DEFAULT_PORT",
		Usage:   "Default port to use for the default target that is created.",
	})

	f.IntVar(&base.IntVar{
		Name:    "target-session-connection-limit",
		Target:  &c.flagTargetSessionConnectionLimit,
		Default: -1,
		EnvVar:  "BOUNDARY_DEV_TARGET_SESSION_CONNECTION_LIMIT",
		Usage:   "Maximum number of connections per session to set on the default target. -1 means unlimited.",
	})

	f.IntVar(&base.IntVar{
		Name:   "target-session-max-seconds",
		Target: &c.flagTargetSessionMaxSeconds,
		EnvVar: "BOUNDARY_DEV_TARGET_SESSION_MAX_SECONDS",
		Usage:  "Max seconds to use for sessions on the default target.",
	})

	f.StringVar(&base.StringVar{
		Name:   "cluster-listen-address",
		Target: &c.flagControllerClusterListenAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_CLUSTER_LISTEN_ADDRESS",
		Usage:  "Address to bind to for controller \"cluster\" purpose. If this begins with a forward slash, it will be assumed to be a Unix domain socket path.",
	})

	f.StringVar(&base.StringVar{
		Name:   "controller-public-cluster-address",
		Target: &c.flagControllerPublicClusterAddr,
		EnvVar: "BOUNDARY_DEV_CONTROLLER_PUBLIC_CLUSTER_ADDRESS",
		Usage:  "Public address at which the controller is reachable for cluster tasks (like worker connections).",
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

	f.StringVar(&base.StringVar{
		Name:   "database-url",
		Target: &c.flagDatabaseUrl,
		Usage:  `If set, specifies the URL used to connect to the database for initialization (otherwise a Docker container will be started). This can refer to a file on disk (file://) from which a URL will be read; an env var (env://) from which the URL will be read; or a direct database URL.`,
	})
	f.StringVar(&base.StringVar{
		Name:   "database-image",
		Target: &c.flagDatabaseImage,
		Usage:  `Specifies a container image to be utilized. Must be in <repo>:<tag> format`,
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
		return base.CommandUserError
	}

	// childShutdownCh := make(chan struct{})

	c.Config, err = config.DevCombined()
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating controller dev config: %w", err).Error())
		return base.CommandUserError
	}
	if c.flagIdSuffix != "" {
		if len(c.flagIdSuffix) != 10 {
			c.UI.Error("Invalid ID suffix, must be exactly 10 characters")
			return base.CommandUserError
		}
		if !handlers.ValidId("abc", "abc_"+c.flagIdSuffix) {
			c.UI.Error("Invalid ID suffix, must be in the set A-Za-z0-9")
			return base.CommandUserError
		}
		c.DevAuthMethodId = fmt.Sprintf("%s_%s", password.AuthMethodPrefix, c.flagIdSuffix)
		c.DevUserId = fmt.Sprintf("%s_%s", iam.UserPrefix, c.flagIdSuffix)
		c.DevUnprivilegedUserId = "u_" + strutil.Reverse(strings.TrimPrefix(c.DevUserId, "u_"))
		c.DevOrgId = fmt.Sprintf("%s_%s", scope.Org.Prefix(), c.flagIdSuffix)
		c.DevProjectId = fmt.Sprintf("%s_%s", scope.Project.Prefix(), c.flagIdSuffix)
		c.DevHostCatalogId = fmt.Sprintf("%s_%s", static.HostCatalogPrefix, c.flagIdSuffix)
		c.DevHostSetId = fmt.Sprintf("%s_%s", static.HostSetPrefix, c.flagIdSuffix)
		c.DevHostId = fmt.Sprintf("%s_%s", static.HostPrefix, c.flagIdSuffix)
		c.DevTargetId = fmt.Sprintf("%s_%s", target.TcpTargetPrefix, c.flagIdSuffix)
	}
	if c.flagLoginName != "" {
		c.DevLoginName = c.flagLoginName
	}
	if c.flagPassword != "" {
		c.DevPassword = c.flagPassword
	}
	if c.flagUnprivilegedLoginName != "" {
		c.DevUnprivilegedLoginName = c.flagUnprivilegedLoginName
	}
	if c.flagUnprivilegedPassword != "" {
		c.DevUnprivilegedPassword = c.flagUnprivilegedPassword
	}
	c.DevTargetDefaultPort = c.flagTargetDefaultPort
	host, port, err := net.SplitHostPort(c.flagHostAddress)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port") {
			c.UI.Error(fmt.Errorf("Invalid host address specified: %w", err).Error())
			return base.CommandUserError
		}
		host = c.flagHostAddress
	}
	if port != "" {
		c.UI.Error(`Port must not be specified as part of the dev host address`)
		return base.CommandUserError
	}
	if c.flagTargetSessionMaxSeconds < 0 {
		c.UI.Error(`Specified target session max sessions cannot be negative`)
		return base.CommandUserError
	}
	c.DevTargetSessionMaxSeconds = c.flagTargetSessionMaxSeconds
	c.DevTargetSessionConnectionLimit = c.flagTargetSessionConnectionLimit
	c.DevHostAddress = host

	c.Config.PassthroughDirectory = c.flagPassthroughDirectory

	for _, l := range c.Config.Listeners {
		if len(l.Purpose) != 1 {
			c.UI.Error("Only one purpose supported for each listener")
			return base.CommandUserError
		}
		switch l.Purpose[0] {
		case "api":
			if c.flagControllerAPIListenAddr != "" {
				l.Address = c.flagControllerAPIListenAddr
			}
			if strings.HasPrefix(l.Address, "/") {
				l.Type = "unix"
			}

		case "cluster":
			if c.flagControllerClusterListenAddr != "" {
				l.Address = c.flagControllerClusterListenAddr
				c.Config.Worker.Controllers = []string{l.Address}
			} else {
				l.Address = "127.0.0.1:9201"
			}
			if strings.HasPrefix(l.Address, "/") {
				l.Type = "unix"
			}

		case "proxy":
			if c.flagWorkerProxyListenAddr != "" {
				l.Address = c.flagWorkerProxyListenAddr
			} else {
				l.Address = "127.0.0.1:9202"
			}
		}
	}

	if err := c.SetupControllerPublicClusterAddress(c.Config, c.flagControllerPublicClusterAddr); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	c.InfoKeys = append(c.InfoKeys, "controller public cluster addr")
	c.Info["controller public cluster addr"] = c.Config.Controller.PublicClusterAddr

	if err := c.SetupWorkerPublicAddress(c.Config, c.flagWorkerPublicAddr); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	c.InfoKeys = append(c.InfoKeys, "worker public proxy addr")
	c.Info["worker public proxy addr"] = c.Config.Worker.PublicAddr

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, "", ""); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	base.StartMemProfiler(c.Logger)

	if err := c.SetupMetrics(c.UI, c.Config.Telemetry); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	if c.flagRecoveryKey != "" {
		c.Config.DevRecoveryKey = c.flagRecoveryKey
	}
	if err := c.SetupKMSes(c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if c.RootKms == nil {
		c.UI.Error("Controller KMS not found after parsing KMS blocks")
		return base.CommandUserError
	}
	if c.WorkerAuthKms == nil {
		c.UI.Error("Worker Auth KMS not found after parsing KMS blocks")
		return base.CommandUserError
	}
	c.InfoKeys = append(c.InfoKeys, "[Controller] AEAD Key Bytes")
	c.Info["[Controller] AEAD Key Bytes"] = c.Config.DevControllerKey
	c.InfoKeys = append(c.InfoKeys, "[Worker-Auth] AEAD Key Bytes")
	c.Info["[Worker-Auth] AEAD Key Bytes"] = c.Config.DevWorkerAuthKey
	c.InfoKeys = append(c.InfoKeys, "[Recovery] AEAD Key Bytes")
	c.Info["[Recovery] AEAD Key Bytes"] = c.Config.DevRecoveryKey

	// Initialize the listeners
	if err := c.SetupListeners(c.UI, c.Config.SharedConfig, []string{"api", "cluster", "proxy"}); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return base.CommandUserError
	}

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	var opts []docker.Option
	switch c.flagDatabaseUrl {
	case "":
		if c.flagDisableDatabaseDestruction {
			opts = append(opts, docker.WithSkipDatabaseDestruction())
		}
		if c.flagDatabaseImage != "" {
			opts = append(opts, docker.WithDatabaseImage(c.flagDatabaseImage))
			if err := c.CreateDevDatabase(c.Context, opts...); err != nil {
				c.UI.Error(fmt.Errorf("Error creating dev database container %w", err).Error())
				return base.CommandCliError
			}
			c.UI.Error(fmt.Errorf("Error creating dev database container: %w", err).Error())
			return base.CommandCliError
		}
		if !c.flagDisableDatabaseDestruction {
			c.ShutdownFuncs = append(c.ShutdownFuncs, c.DestroyDevDatabase)
		}
	default:
		c.DatabaseUrl, err = config.ParseAddress(c.flagDatabaseUrl)
		if err != nil && err != config.ErrNotAUrl {
			c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
			return base.CommandUserError
		}

		//todo (schristoff): hmmm
		//If no database container image is specified, postgres is used
		opts = append(opts, docker.WithDatabaseImage("postgres"))
		if err := c.CreateDevDatabase(c.Context, opts...); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return base.CommandCliError
		}
	}

	c.PrintInfo(c.UI)
	c.ReleaseLogGate()

	{
		conf := &controller.Config{
			RawConfig: c.Config,
			Server:    c.Server,
		}

		var err error
		c.controller, err = controller.New(conf)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error initializing controller: %w", err).Error())
			return base.CommandCliError
		}

		if err := c.controller.Start(); err != nil {
			retErr := fmt.Errorf("Error starting controller: %w", err)
			if err := c.controller.Shutdown(false); err != nil {
				c.UI.Error(retErr.Error())
				retErr = fmt.Errorf("Error shutting down controller: %w", err)
			}
			c.UI.Error(retErr.Error())
			return base.CommandCliError
		}
	}
	{
		conf := &worker.Config{
			RawConfig: c.Config,
			Server:    c.Server,
		}

		var err error
		c.worker, err = worker.New(conf)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error initializing controller: %w", err).Error())
			return base.CommandCliError
		}

		if err := c.worker.Start(); err != nil {
			retErr := fmt.Errorf("Error starting worker: %w", err)
			if err := c.worker.Shutdown(false); err != nil {
				c.UI.Error(retErr.Error())
				retErr = fmt.Errorf("Error shutting down worker: %w", err)
			}
			c.UI.Error(retErr.Error())
			if err := c.controller.Shutdown(false); err != nil {
				c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
			}
			return base.CommandCliError
		}
	}

	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> Boundary dev environment shutdown triggered")

			if err := c.worker.Shutdown(false); err != nil {
				c.UI.Error(fmt.Errorf("Error shutting down worker: %w", err).Error())
			}

			if err := c.controller.Shutdown(false); err != nil {
				c.UI.Error(fmt.Errorf("Error shutting down controller: %w", err).Error())
			}

			shutdownTriggered = true

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			c.Logger.Info("goroutine trace", "stack", string(buf[:n]))
		}
	}

	return base.CommandSuccess
}
