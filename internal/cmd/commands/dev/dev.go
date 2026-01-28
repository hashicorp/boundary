// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dev

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	atm "sync/atomic"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/cmd/ops"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mitchellh/cli"
	"github.com/mr-tron/base58"
	"github.com/posener/complete"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/proto"
)

const (
	ControllerGeneratedAuthTokenWorkerAuthMechanism = "controller-generated-auth-token"
	WorkerGeneratedAuthTokenWorkerAuthMechanism     = "worker-generated-auth-token"
	KmsWorkerAuthMechanism                          = "kms"
	RandomWorkerAuthMechanism                       = "random"
	DeprecatedKmsWorkerAuthMechanism                = "deprecated-kms"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

var extraSelfTerminationConditionFuncs []func(*Command, chan struct{})

type Command struct {
	*base.Server
	opsServer *ops.Server

	SighupCh      chan struct{}
	childSighupCh []chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	Config     *config.Config
	controller *controller.Controller
	worker     *worker.Worker

	flagLogLevel                                       string
	flagLogFormat                                      string
	flagCombineLogs                                    bool
	flagLoginName                                      string
	flagPassword                                       string
	flagUnprivilegedLoginName                          string
	flagUnprivilegedPassword                           string
	flagIdSuffix                                       string
	flagSecondaryIdSuffix                              string
	flagHostAddress                                    string
	flagTargetDefaultPort                              uint16
	flagTargetSessionMaxSeconds                        int64
	flagTargetSessionConnectionLimit                   int64
	flagControllerApiListenAddr                        string
	flagControllerClusterListenAddr                    string
	flagControllerPublicClusterAddr                    string
	flagControllerOnly                                 bool
	flagWorkerAuthKey                                  string
	flagWorkerProxyListenAddr                          string
	flagWorkerPublicAddr                               string
	flagOpsListenAddr                                  string
	flagUiPassthroughDir                               string
	flagRecoveryKey                                    string
	flagDatabaseUrl                                    string
	flagContainerImage                                 string
	flagDisableDatabaseDestruction                     bool
	flagEventFormat                                    string
	flagAudit                                          string
	flagObservations                                   string
	flagTelemetry                                      string
	flagSysEvents                                      string
	flagEveryEventAllowFilters                         []string
	flagEveryEventDenyFilters                          []string
	flagCreateLoopbackPlugin                           bool
	flagPluginExecutionDir                             string
	flagSkipPlugins                                    bool
	flagSkipOidcAuthMethodCreation                     bool
	flagSkipLdapAuthMethodCreation                     bool
	flagSkipAliasTargetCreation                        bool
	flagWorkerDnsServer                                string
	flagWorkerAuthMethod                               string
	flagWorkerAuthStorageDir                           string
	flagWorkerAuthStorageSkipCleanup                   bool
	flagWorkerAuthWorkerRotationInterval               time.Duration
	flagWorkerAuthCaCertificateLifetime                time.Duration
	flagWorkerAuthDebuggingEnabled                     bool
	flagWorkerRecordingStorageDir                      string
	flagSshKnownHostsPath                              string
	flagWorkerRecordingStorageMinimumAvailableCapacity string
	flagBsrKey                                         string
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
		Usage:   `If set, auto-created resources will use this value for their identifier (along with their resource-specific prefix). Must be 10 alphanumeric characters. As an example, if this is set to "1234567890", the generated password auth method ID will be "ampw_1234567890", the generated TCP target ID will be "ttcp_1234567890", and so on. Must be different from -secondary-id-suffix (BOUNDARY_DEV_SECONDARY_ID_SUFFIX).`,
	})

	f.StringVar(&base.StringVar{
		Name:    "secondary-id-suffix",
		Target:  &c.flagSecondaryIdSuffix,
		Default: "0987654321",
		EnvVar:  "BOUNDARY_DEV_SECONDARY_ID_SUFFIX",
		Usage:   `If set, secondary auto-created resources will use this value for their identifier (along with their resource-specific prefix). Must be 10 alphanumeric characters. Currently only used for the target resource. Must be different from -id-suffix (BOUNDARY_DEV_ID_SUFFIX).`,
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
		Target: &c.flagControllerApiListenAddr,
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

	f.Uint16Var(&base.Uint16Var{
		Name:    "target-default-port",
		Default: 22,
		Target:  &c.flagTargetDefaultPort,
		EnvVar:  "BOUNDARY_DEV_TARGET_DEFAULT_PORT",
		Usage:   "Default port to use for the default target that is created.",
	})

	f.Int64Var(&base.Int64Var{
		Name:    "target-session-connection-limit",
		Target:  &c.flagTargetSessionConnectionLimit,
		Default: -1,
		EnvVar:  "BOUNDARY_DEV_TARGET_SESSION_CONNECTION_LIMIT",
		Usage:   "Maximum number of connections per session to set on the default target. -1 means unlimited.",
	})

	f.Int64Var(&base.Int64Var{
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
		Name:   "ops-listen-address",
		Target: &c.flagOpsListenAddr,
		EnvVar: "BOUNDARY_DEV_OPS_LISTEN_ADDRESS",
		Usage:  "Address to bind to for \"ops\" purpose. If this begins with a forward slash, it will be assumed to be a Unix domain socket path.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "controller-only",
		Target: &c.flagControllerOnly,
		Usage:  "If set, only a dev controller will be started instead of both a dev controller and dev worker.",
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

	f.StringVar(&base.StringVar{
		Name:   "worker-auth-key",
		Target: &c.flagWorkerAuthKey,
		EnvVar: "BOUNDARY_DEV_WORKER_AUTH_KEY",
		Usage:  "If set, a valid base64-encoded AES key to be used for worker-auth purposes",
	})

	f.StringVar(&base.StringVar{
		Name:   "bsr-key",
		Target: &c.flagBsrKey,
		EnvVar: "BOUNDARY_DEV_BSR_KEY",
		Usage:  "If set, a valid base64-encoded AES key to be used for bsr purposes",
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
		Name:   "ui-passthrough-dir",
		Target: &c.flagUiPassthroughDir,
		EnvVar: "BOUNDARY_DEV_UI_PASSTHROUGH_DIR",
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
		Name:   "container-image",
		Target: &c.flagContainerImage,
		Usage:  `Specifies a container image to be utilized. Must be in <repo>:<tag> format`,
	})
	f.StringVar(&base.StringVar{
		Name:       "event-format",
		Target:     &c.flagEventFormat,
		Completion: complete.PredictSet("cloudevents-json", "cloudevents-text", "hclog-text", "hclog-json"),
		Usage:      `Event format. Supported values are "cloudevents-json", "cloudevents-text", "hclog-json", and "hclog-text".`,
	})
	f.StringVar(&base.StringVar{
		Name:       "observation-events",
		Target:     &c.flagObservations,
		Completion: complete.PredictSet("true", "false"),
		Usage:      `Emit observation events. Supported values are "true" and "false".`,
	})
	f.StringVar(&base.StringVar{
		Name:       "telemetry-events",
		Target:     &c.flagTelemetry,
		Completion: complete.PredictSet("true", "false"),
		Usage:      `Emit telemetry events. Supported values are "true" and "false".`,
	})
	f.StringVar(&base.StringVar{
		Name:       "audit-events",
		Target:     &c.flagAudit,
		Completion: complete.PredictSet("true", "false"),
		Usage:      `Emit audit events. Supported values are "true" and "false".`,
	})
	f.StringVar(&base.StringVar{
		Name:       "system-events",
		Target:     &c.flagSysEvents,
		Completion: complete.PredictSet("true", "false"),
		Usage:      `Emit system events. Supported values are "true" and "false".`,
	})
	f.StringSliceVar(&base.StringSliceVar{
		Name:   "event-allow-filter",
		Target: &c.flagEveryEventAllowFilters,
		Usage:  `The optional every event allow filter. May be specified multiple times.`,
	})
	f.StringSliceVar(&base.StringSliceVar{
		Name:   "event-deny-filter",
		Target: &c.flagEveryEventDenyFilters,
		Usage:  `The optional every event deny filter. May be specified multiple times.`,
	})

	f.StringVar(&base.StringVar{
		Name:   "plugin-execution-dir",
		Target: &c.flagPluginExecutionDir,
		EnvVar: "BOUNDARY_DEV_PLUGIN_EXECUTION_DIR",
		Usage:  "Specifies where Boundary should write plugins that it is executing; if not set defaults to system temp directory.",
	})
	f.BoolVar(&base.BoolVar{
		Name:   "skip-plugins",
		Target: &c.flagSkipPlugins,
		Usage:  "Skip loading compiled-in plugins. This does not prevent loopback plugins from being loaded if enabled.",
		Hidden: true,
	})
	f.BoolVar(&base.BoolVar{
		Name:   "skip-oidc-auth-method-creation",
		Target: &c.flagSkipOidcAuthMethodCreation,
		Usage:  "Skip creating a test OIDC auth method. This is useful if e.g. running a Unix API listener.",
	})
	f.BoolVar(&base.BoolVar{
		Name:   "skip-ldap-auth-method-creation",
		Target: &c.flagSkipLdapAuthMethodCreation,
		Usage:  "Skip creating a test LDAP auth method. This is useful if e.g. running a Unix API listener.",
	})
	f.BoolVar(&base.BoolVar{
		Name:   "skip-alias-target-creation",
		Target: &c.flagSkipAliasTargetCreation,
		Usage:  "Skip creating test targets using an alias.",
		Hidden: true,
	})
	f.StringVar(&base.StringVar{
		Name:   "worker-dns-server",
		Target: &c.flagWorkerDnsServer,
		Usage:  "Use a custom DNS server when workers resolve endpoints.",
		Hidden: true,
	})

	f.StringVar(&base.StringVar{
		Name:       "worker-auth-method",
		Target:     &c.flagWorkerAuthMethod,
		Default:    RandomWorkerAuthMechanism,
		Completion: complete.PredictSet(ControllerGeneratedAuthTokenWorkerAuthMechanism, WorkerGeneratedAuthTokenWorkerAuthMechanism, KmsWorkerAuthMechanism, RandomWorkerAuthMechanism),
		Usage:      `Allows specifying how the generated worker will authenticate to the controller.`,
	})
	f.StringVar(&base.StringVar{
		Name:   "worker-auth-storage-dir",
		Target: &c.flagWorkerAuthStorageDir,
		Usage:  "Specifies the directory to store worker authentication credentials in dev mode. Setting this will make use of file storage at the specified location; otherwise in-memory storage or a temporary directory will be used.",
	})

	f.StringVar(&base.StringVar{
		Name:   "worker-recording-storage-dir",
		Target: &c.flagWorkerRecordingStorageDir,
		Usage:  "Specifies the directory to store worker session recordings in dev mode. If not provided a temp directory will be created. Session recording is an Enterprise-only feature.",
	})

	f.StringVar(&base.StringVar{
		Name:   "worker-ssh-known-hosts-path",
		Target: &c.flagSshKnownHostsPath,
		Usage:  "Specifies the path of the known_hosts file to be used by the worker for SSH host key verification of an SSH target in dev mode. SSH targets and SSH credential injection are Enterprise-only features.",
	})

	f.StringVar(&base.StringVar{
		Name:   "worker-recording-storage-minimum-available-capacity",
		Target: &c.flagWorkerRecordingStorageMinimumAvailableCapacity,
		Usage:  "Specifies the minimum amount of available disk space a worker needs in the recording storage directory to process sessions with session recording enabled. Input should be a capacity string: 4kib or 3GB. Defaults to 500mib.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "worker-auth-storage-skip-cleanup",
		Target: &c.flagWorkerAuthStorageSkipCleanup,
		Usage:  "Prevents deletion of worker credential storage directory if set. Has no effect unless worker-auth-storage-dir is specified.",
	})
	f.BoolVar(&base.BoolVar{
		Name:   "worker-auth-enable-debugging",
		Target: &c.flagWorkerAuthDebuggingEnabled,
		Usage:  "Turn on debug logging of the worker authentication process.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "create-loopback-plugin",
		Target: &c.flagCreateLoopbackPlugin,
		Hidden: true,
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

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	const op = "dev.(Command).Run"
	c.CombineLogs = c.flagCombineLogs

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	switch c.flagControllerOnly {
	case true:
		c.Config, err = config.DevController(
			config.WithObservationsEnabled(true),
			config.WithSysEventsEnabled(true),
			config.WithRandomReader(c.SecureRandomReader),
		)
	default:
		c.Config, err = config.DevCombined(config.WithRandomReader(c.SecureRandomReader))
	}
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating controller dev config: %w", err).Error())
		return base.CommandUserError
	}

	if c.flagWorkerAuthKey != "" {
		c.Config.DevWorkerAuthKey = c.flagWorkerAuthKey
		for _, kms := range c.Config.Seals {
			if strutil.StrListContains(kms.Purpose, globals.KmsPurposeWorkerAuth) {
				kms.Config["key"] = c.flagWorkerAuthKey
			}
		}
	}

	if c.flagBsrKey != "" {
		c.Config.DevBsrKey = c.flagBsrKey
		for _, kms := range c.Config.Seals {
			if strutil.StrListContains(kms.Purpose, globals.KmsPurposeBsr) {
				kms.Config["key"] = c.flagBsrKey
			}
		}
	}

	c.WorkerAuthDebuggingEnabled.Store(c.flagWorkerAuthDebuggingEnabled)

	c.DevLoginName = c.flagLoginName
	c.DevPassword = c.flagPassword
	c.DevUnprivilegedLoginName = c.flagUnprivilegedLoginName
	c.DevUnprivilegedPassword = c.flagUnprivilegedPassword
	c.DevTargetDefaultPort = c.flagTargetDefaultPort
	c.Config.Plugins.ExecutionDir = c.flagPluginExecutionDir

	if !c.flagControllerOnly {
		c.Config.Worker.SshKnownHostsPath = c.flagSshKnownHostsPath
		c.Config.Worker.AuthStoragePath = c.flagWorkerAuthStorageDir
		c.Config.Worker.RecordingStoragePath = c.flagWorkerRecordingStorageDir
		c.Config.Worker.RecordingStorageMinimumAvailableCapacity = c.flagWorkerRecordingStorageMinimumAvailableCapacity

		if c.Config.Worker.RecordingStoragePath == "" {
			// Create a temp dir for recording storage
			const pattern = "recordingstorage"
			c.Config.Worker.RecordingStoragePath, err = os.MkdirTemp("", pattern)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error creating storage temp dir: %w", err).Error())
				return base.CommandCliError
			}
			c.ShutdownFuncs = append(c.ShutdownFuncs, func() error { return os.RemoveAll(c.Config.Worker.RecordingStoragePath) })
		}
	}

	if c.flagIdSuffix != "" {
		if len(c.flagIdSuffix) != 10 {
			c.UI.Error("Invalid ID suffix, must be exactly 10 characters")
			return base.CommandUserError
		}
		if !handlers.ValidId(handlers.Id("abc_"+c.flagIdSuffix), "abc") {
			c.UI.Error("Invalid ID suffix, must be in the set A-Za-z0-9")
			return base.CommandUserError
		}
		c.DevPasswordAuthMethodId = fmt.Sprintf("%s_%s", globals.PasswordAuthMethodPrefix, c.flagIdSuffix)
		c.DevOidcAuthMethodId = fmt.Sprintf("%s_%s", globals.OidcAuthMethodPrefix, c.flagIdSuffix)
		c.DevLdapAuthMethodId = fmt.Sprintf("%s_%s", globals.LdapAuthMethodPrefix, c.flagIdSuffix)
		c.DevUserId = fmt.Sprintf("%s_%s", globals.UserPrefix, c.flagIdSuffix)
		c.DevPasswordAccountId = fmt.Sprintf("%s_%s", globals.PasswordAccountPrefix, c.flagIdSuffix)
		c.DevOidcAccountId = fmt.Sprintf("%s_%s", globals.OidcAccountPrefix, c.flagIdSuffix)
		c.DevUnprivilegedUserId = "u_" + strutil.Reverse(strings.TrimPrefix(c.DevUserId, "u_"))
		c.DevUnprivilegedPasswordAccountId = fmt.Sprintf("%s_", globals.PasswordAccountPrefix) + strutil.Reverse(strings.TrimPrefix(c.DevPasswordAccountId, fmt.Sprintf("%s_", globals.PasswordAccountPrefix)))
		c.DevUnprivilegedOidcAccountId = fmt.Sprintf("%s_", globals.OidcAccountPrefix) + strutil.Reverse(strings.TrimPrefix(c.DevOidcAccountId, fmt.Sprintf("%s_", globals.OidcAccountPrefix)))
		c.DevOrgId = fmt.Sprintf("%s_%s", scope.Org.Prefix(), c.flagIdSuffix)
		c.DevProjectId = fmt.Sprintf("%s_%s", scope.Project.Prefix(), c.flagIdSuffix)
		c.DevHostCatalogId = fmt.Sprintf("%s_%s", globals.StaticHostCatalogPrefix, c.flagIdSuffix)
		c.DevHostSetId = fmt.Sprintf("%s_%s", globals.StaticHostSetPrefix, c.flagIdSuffix)
		c.DevHostId = fmt.Sprintf("%s_%s", globals.StaticHostPrefix, c.flagIdSuffix)
		c.DevTargetId = fmt.Sprintf("%s_%s", globals.TcpTargetPrefix, c.flagIdSuffix)
	}
	if c.flagSecondaryIdSuffix != "" {
		if len(c.flagSecondaryIdSuffix) != 10 {
			c.UI.Error("Invalid secondary ID suffix, must be exactly 10 characters")
			return base.CommandUserError
		}
		if !handlers.ValidId(handlers.Id("abc_"+c.flagSecondaryIdSuffix), "abc") {
			c.UI.Error("Invalid secondary ID suffix, must be in the set A-Za-z0-9")
			return base.CommandUserError
		}
		c.DevSecondaryTargetId = fmt.Sprintf("%s_%s", globals.TcpTargetPrefix, c.flagSecondaryIdSuffix)
	}

	if c.flagIdSuffix != "" && c.flagSecondaryIdSuffix != "" &&
		strings.EqualFold(c.flagIdSuffix, c.flagSecondaryIdSuffix) {
		c.UI.Error("Primary and secondary ID suffixes are equal, must be distinct")
		return base.CommandUserError
	}

	host, port, err := util.SplitHostPort(c.flagHostAddress)
	if err != nil && !errors.Is(err, util.ErrMissingPort) {
		c.UI.Error(fmt.Errorf("Invalid host address specified: %w", err).Error())
		return base.CommandUserError
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

	c.Config.DevUiPassthroughDir = c.flagUiPassthroughDir

	c.SkipPlugins = c.flagSkipPlugins
	c.SkipAliasTargetCreation = c.flagSkipAliasTargetCreation
	c.WorkerDnsServer = c.flagWorkerDnsServer

	for _, l := range c.Config.Listeners {
		if len(l.Purpose) != 1 {
			c.UI.Error("Only one purpose supported for each listener")
			return base.CommandUserError
		}
		switch l.Purpose[0] {
		case "api":
			if c.flagControllerApiListenAddr != "" {
				l.Address = c.flagControllerApiListenAddr
			}
			if strings.HasPrefix(l.Address, "/") {
				l.Type = "unix"
			}

		case "cluster":
			if c.flagControllerClusterListenAddr != "" {
				l.Address = c.flagControllerClusterListenAddr
				if !c.flagControllerOnly {
					c.Config.Worker.InitialUpstreams = []string{l.Address}
				}
			} else {
				l.Address = "127.0.0.1:9201"
			}
			if strings.HasPrefix(l.Address, "/") {
				l.Type = "unix"
			}

		case "ops":
			if c.flagOpsListenAddr != "" {
				l.Address = c.flagOpsListenAddr
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

	if err := c.Config.SetupControllerPublicClusterAddress(c.flagControllerPublicClusterAddr); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	c.InfoKeys = append(c.InfoKeys, "controller public cluster addr")
	c.Info["controller public cluster addr"] = c.Config.Controller.PublicClusterAddr

	if err := c.SetupWorkerPublicAddress(c.Config, c.flagWorkerPublicAddr); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if !c.flagControllerOnly {
		c.InfoKeys = append(c.InfoKeys, "worker public proxy addr")
		c.Info["worker public proxy addr"] = c.Config.Worker.PublicAddr
	}

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, "", ""); err != nil {
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

	eventFlags, err := base.NewEventFlags(event.TextSinkFormat, base.ComposedOfEventArgs{
		Format:       c.flagEventFormat,
		Audit:        c.flagAudit,
		Observations: c.flagObservations,
		Telemetry:    c.flagTelemetry,
		SysEvents:    c.flagSysEvents,
		Allow:        c.flagEveryEventAllowFilters,
		Deny:         c.flagEveryEventDenyFilters,
	})
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	base.StartMemProfiler(c.Context)

	if err := c.SetupEventing(
		c.Context,
		c.Logger,
		c.StderrLock,
		serverName,
		base.WithEventerConfig(c.Config.Eventing),
		base.WithEventFlags(eventFlags),
		base.WithEventGating(true)); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	base.StartPprof(c.Context)

	if c.flagRecoveryKey != "" {
		c.Config.DevRecoveryKey = c.flagRecoveryKey
	}
	if err := c.SetupKMSes(c.Context, c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if c.RootKms == nil {
		c.UI.Error("Controller KMS not found after parsing KMS blocks")
		return base.CommandUserError
	}

	if c.flagWorkerAuthMethod != DeprecatedKmsWorkerAuthMechanism &&
		c.flagWorkerAuthMethod != KmsWorkerAuthMechanism {
		// Flip a coin to decide between file storage and inmem. It's
		// transparent to users, but keeps both exercised.
		randStorage := rand.New(rand.NewSource(time.Now().UnixMicro())).Intn(2)
		if randStorage == 0 {
			const pattern = "nodeenrollment"
			c.Config.Worker.AuthStoragePath, err = os.MkdirTemp("", pattern)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error creating temp dir: %w", err).Error())
				return base.CommandCliError
			}
			if !c.flagWorkerAuthStorageSkipCleanup && c.flagWorkerAuthStorageDir != "" {
				c.ShutdownFuncs = append(c.ShutdownFuncs, func() error { return os.RemoveAll(c.Config.Worker.AuthStoragePath) })
			}
		}
	}

	c.InfoKeys = append(c.InfoKeys, "[Root] AEAD Key Bytes")
	c.Info["[Root] AEAD Key Bytes"] = c.Config.DevControllerKey
	c.InfoKeys = append(c.InfoKeys, "[Recovery] AEAD Key Bytes")
	c.Info["[Recovery] AEAD Key Bytes"] = c.Config.DevRecoveryKey
	c.InfoKeys = append(c.InfoKeys, "[Worker-Auth] AEAD Key Bytes")
	c.Info["[Worker-Auth] AEAD Key Bytes"] = c.Config.DevWorkerAuthKey
	c.InfoKeys = append(c.InfoKeys, "[Bsr] AEAD Key Bytes")
	c.Info["[Bsr] AEAD Key Bytes"] = c.Config.DevBsrKey
	if c.Config.DevWorkerAuthStorageKey != "" {
		c.InfoKeys = append(c.InfoKeys, "[Worker-Auth-Storage] AEAD Key Bytes")
		c.Info["[Worker-Auth-Storage] AEAD Key Bytes"] = c.Config.DevWorkerAuthStorageKey
	}

	// Initialize the listeners
	if err := c.SetupListeners(c.UI, c.Config.SharedConfig, []string{"api", "cluster", "proxy", "ops"}); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	// Write out the PID to the file now that server has successfully started
	if err := c.StorePidFile(c.Config.PidFile); err != nil {
		c.UI.Error(fmt.Errorf("Error storing PID: %w", err).Error())
		return base.CommandUserError
	}

	var opts []base.Option
	if c.flagSkipOidcAuthMethodCreation {
		opts = append(opts, base.WithSkipOidcAuthMethodCreation())
	}
	if c.flagSkipLdapAuthMethodCreation {
		opts = append(opts, base.WithSkipLdapAuthMethodCreation())
	}
	if c.flagCreateLoopbackPlugin {
		c.DevLoopbackPluginId = "pl_1234567890"
		c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginLoopback)
		c.Config.Controller.Scheduler.JobRunIntervalDuration = 100 * time.Millisecond
		c.Info["Generated Dev Loopback plugin id"] = c.DevLoopbackPluginId
	}
	switch c.flagDatabaseUrl {
	case "":
		if c.flagDisableDatabaseDestruction {
			opts = append(opts, base.WithSkipDatabaseDestruction())
		}
		if c.flagContainerImage != "" {
			opts = append(opts, base.WithContainerImage(c.flagContainerImage))
		}
		if err := c.CreateDevDatabase(c.Context, opts...); err != nil {
			c.UI.Error(fmt.Errorf("Error creating dev database container: %w", err).Error())
			return base.CommandCliError
		}

		if !c.flagDisableDatabaseDestruction {
			// Use background context here so that we don't immediately fail to
			// cleanup if the command context has already been canceled
			c.ShutdownFuncs = append(c.ShutdownFuncs, func() error { return c.DestroyDevDatabase(context.Background()) })
		}
	default:
		c.DatabaseUrl, err = parseutil.ParsePath(c.flagDatabaseUrl)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
			return base.CommandUserError
		}
		if err := c.CreateDevDatabase(c.Context, opts...); err != nil {
			c.UI.Error(fmt.Errorf("Error connecting to database: %w", err).Error())
			return base.CommandCliError
		}
	}

	{
		c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginAws, base.EnabledPluginHostAzure, base.EnabledPluginGCP)
		if base.MinioEnabled {
			c.EnabledPlugins = append(c.EnabledPlugins, base.EnabledPluginMinio)
		}
		conf := &controller.Config{
			RawConfig: c.Config,
			Server:    c.Server,
			TestOverrideWorkerAuthCaCertificateLifetime: c.flagWorkerAuthCaCertificateLifetime,
		}

		var err error
		c.controller, err = controller.New(c.Context, conf)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error initializing controller: %w", err).Error())
			return base.CommandCliError
		}

		if err := c.controller.Start(); err != nil {
			retErr := fmt.Errorf("Error starting controller: %w", err)
			if err := c.controller.Shutdown(); err != nil {
				c.UI.Error(retErr.Error())
				retErr = fmt.Errorf("Error shutting down controller: %w", err)
			}
			c.UI.Error(retErr.Error())
			return base.CommandCliError
		}
	}

	errorEncountered := atomic.NewBool(false)

	if !c.flagControllerOnly {
		conf := &worker.Config{
			RawConfig: c.Config,
			Server:    c.Server,
		}

		var err error
		c.worker, err = worker.New(c.Context, conf)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error initializing worker: %w", err).Error())
			return base.CommandCliError
		}
		c.worker.TestOverrideAuthRotationPeriod = c.flagWorkerAuthWorkerRotationInterval

		if c.flagWorkerAuthMethod == RandomWorkerAuthMechanism {
			// Flip a coin. Use one method or the other; it's transparent to
			// users, but keeps both exercised.
			randPki := rand.New(rand.NewSource(time.Now().UnixMicro())).Intn(3)
			switch randPki {
			case 0:
				c.flagWorkerAuthMethod = ControllerGeneratedAuthTokenWorkerAuthMechanism
			case 1:
				c.flagWorkerAuthMethod = WorkerGeneratedAuthTokenWorkerAuthMechanism
			default:
				c.flagWorkerAuthMethod = KmsWorkerAuthMechanism
			}
		}
		switch c.flagWorkerAuthMethod {
		case ControllerGeneratedAuthTokenWorkerAuthMechanism:
			// Controller-led
			serversRepo, err := c.controller.ServersRepoFn()
			if err != nil {
				c.UI.Error(fmt.Errorf("Error instantiating server repo: %w", err).Error())
				if err := c.controller.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
				}
				return base.CommandCliError
			}

			// Create the worker in the database and fetch an activation token
			worker, err := serversRepo.CreateWorker(c.Context, &server.Worker{
				Worker: &store.Worker{
					ScopeId: scope.Global.String(),
				},
			}, server.WithCreateControllerLedActivationToken(true), server.WithRandomReader(c.SecureRandomReader))
			if err != nil {
				c.UI.Error(fmt.Errorf("Error creating worker in database: %w", err).Error())
				if err := c.controller.Shutdown(); err != nil {
					c.UI.Error(fmt.Errorf("Error with controller shutdown: %w", err).Error())
				}
				return base.CommandCliError
			}

			// Set the activation token in the config and nil out the worker
			// auth KMS so we don't use it via PKI-KMS
			c.WorkerAuthKms = nil
			conf.RawConfig.Worker.ControllerGeneratedActivationToken = worker.ControllerGeneratedActivationToken

		case WorkerGeneratedAuthTokenWorkerAuthMechanism:
			// Clear this out as presence of it causes PKI-KMS behavior
			c.WorkerAuthKms = nil

		case KmsWorkerAuthMechanism, DeprecatedKmsWorkerAuthMechanism:
			if c.WorkerAuthKms == nil {
				c.UI.Error("Worker Auth KMS not found after parsing KMS blocks")
				return base.CommandUserError
			}
		}

		if err := c.worker.Start(); err != nil {
			retErr := fmt.Errorf("Error starting worker: %w", err)
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

		if c.flagWorkerAuthMethod != DeprecatedKmsWorkerAuthMechanism {
			c.InfoKeys = append(c.InfoKeys, "worker auth current key id")
			c.Info["worker auth current key id"] = c.worker.WorkerAuthCurrentKeyId.Load()
			c.InfoKeys = append(c.InfoKeys, "worker auth storage path")
			if c.Config.Worker.AuthStoragePath != "" {
				c.Info["worker auth storage path"] = c.Config.Worker.AuthStoragePath
			} else {
				c.Info["worker auth storage path"] = "(in-memory)"
			}

			if c.flagWorkerAuthMethod == WorkerGeneratedAuthTokenWorkerAuthMechanism {
				req := c.worker.WorkerAuthRegistrationRequest
				if req == "" {
					c.UI.Error("No worker auth registration request found at worker start time")
					return base.CommandCliError
				}

				if c.Config.Worker.AuthStoragePath != "" {
					if err := c.StoreWorkerAuthReq(c.worker.WorkerAuthRegistrationRequest, c.Config.Worker.AuthStoragePath); err != nil {
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

				go func() {
					for {
						select {
						case <-c.Context.Done():
							return
						case <-time.After(time.Second):
							if err := authorizeWorker(c.Context, c.controller, req); err != nil {
								c.UI.Error(fmt.Errorf("Error authorizing node: %w", err).Error())
								errorEncountered.Store(true)
								return
							}
							return
						}
					}
				}()
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
		c.UI.Error(fmt.Errorf("Failed to start ops listeners: %w", err).Error())
		return base.CommandCliError
	}
	c.opsServer = opsServer
	c.opsServer.Start()

	var shutdownCompleted atm.Bool
	shutdownTriggerCount := 0

	var workerShutdownOnce sync.Once
	workerShutdownFunc := func() {
		if err := c.worker.Shutdown(); err != nil {
			c.UI.Error(fmt.Errorf("Error shutting down worker: %w", err).Error())
		}
		if !c.flagWorkerAuthStorageSkipCleanup && c.worker.WorkerAuthStorage != nil {
			if cleanable, ok := c.worker.WorkerAuthStorage.(nodeenrollment.CleanableStorage); ok {
				if err := cleanable.Cleanup(c.Context); err != nil {
					c.UI.Error(fmt.Errorf("Error cleaning up authentication storage: %w", err).Error())
				}
			}
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
		err := c.opsServer.Shutdown()
		if err != nil {
			c.UI.Error(fmt.Errorf("Failed to shutdown ops listeners: %w", err).Error())
		}
	}

	runShutdownLogic := func() {
		switch {
		case shutdownTriggerCount == 1:
			c.ContextCancel()
			go func() {
				if c.Config.Controller != nil {
					c.opsServer.WaitIfHealthExists(c.Config.Controller.GracefulShutdownWaitDuration, c.UI)
				}

				if !c.flagControllerOnly {
					c.UI.Output("==> Boundary dev environment graceful shutdown triggered, interrupt again to enter shutdown")
					workerGracefulShutdownFunc()
				} else {
					c.UI.Output("==> Boundary dev shutdown triggered, interrupt again to force")
				}

				controllerOnce.Do(controllerShutdownFunc)

				shutdownCompleted.Store(true)
			}()
		case shutdownTriggerCount == 2 && !c.flagControllerOnly:
			go func() {
				if !c.flagControllerOnly {
					workerShutdownOnce.Do(workerShutdownFunc)
				}

				if c.Config.Controller != nil {
					controllerOnce.Do(controllerShutdownFunc)
				}
				shutdownCompleted.Store(true)
			}()

		case shutdownTriggerCount >= 2:
			go func() {
				c.UI.Error("Forcing shutdown")
				os.Exit(base.CommandCliError)
			}()
		}
	}

	for _, f := range extraSelfTerminationConditionFuncs {
		f(c, c.ServerSideShutdownCh)
	}

	for !errorEncountered.Load() && !shutdownCompleted.Load() {
		select {
		case <-c.ServerSideShutdownCh:
			c.UI.Output("==> Boundary dev environment self-terminating")
			shutdownTriggerCount++
			runShutdownLogic()

		case <-c.ShutdownCh:
			shutdownTriggerCount++
			runShutdownLogic()

		case <-c.SighupCh:
			c.UI.Output("==> Boundary dev environment does not support configuration reloading, taking no action")

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			event.WriteSysEvent(context.TODO(), op, "goroutine trace", "stack", string(buf[:n]))

		case <-time.After(10 * time.Millisecond):
		}
	}

	return base.CommandSuccess
}

func authorizeWorker(ctx context.Context, c *controller.Controller, request string) error {
	reqBytes, err := base58.FastBase58Decoding(request)
	if err != nil {
		return fmt.Errorf("error base58-decoding fetch node creds next proto value: %w", err)
	}
	// Decode the proto into the request
	req := new(types.FetchNodeCredentialsRequest)
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		return fmt.Errorf("error unmarshaling common name value: %w", err)
	}

	serversRepo, err := c.ServersRepoFn()
	if err != nil {
		return fmt.Errorf("error fetching server repo: %w", err)
	}

	_, err = serversRepo.CreateWorker(ctx, &server.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(req))
	if err != nil {
		return fmt.Errorf("error creating worker: %w", err)
	}

	return err
}
