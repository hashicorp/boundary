package database

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	host_plugin_assets "github.com/hashicorp/boundary/plugins/host"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	external_host_plugins "github.com/hashicorp/boundary/sdk/plugins/host"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*MigrateCommand)(nil)
	_ cli.CommandAutocomplete = (*MigrateCommand)(nil)
)

type MigrateCommand struct {
	*base.Command
	srv *base.Server

	SighupCh   chan struct{}
	ReloadedCh chan struct{}
	SigUSR2Ch  chan struct{}

	Config *config.Config

	// This will be intialized, if needed, in ParseFlagsAndConfig when
	// instantiating a config wrapper, if requested. It's then called as a
	// deferred function on the Run method.
	configWrapperCleanupFunc func() error

	flagConfig             string
	flagConfigKms          string
	flagLogLevel           string
	flagLogFormat          string
	flagMigrationUrl       string
	flagAllowDevMigrations bool
}

func (c *MigrateCommand) Synopsis() string {
	return "Migrate Boundary's database to the most recent schema supported by this binary."
}

func (c *MigrateCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary database migrate [options]",
		"",
		"  Migrate Boundary's database:",
		"",
		"    $ boundary database migrate -config=/etc/boundary/controller.hcl",
		"",
		"  For a full list of examples, please see the documentation.",
	}) + c.Flags().Help()
}

func (c *MigrateCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP)

	f := set.NewFlagSet("Command options")

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

	f = set.NewFlagSet("Migration options")

	f.StringVar(&base.StringVar{
		Name:   "migration-url",
		Target: &c.flagMigrationUrl,
		Usage:  `If set, overrides a migration URL set in config, and specifies the URL used to connect to the database for migration. This can allow different permissions for the user running initialization or migration vs. normal operation. This can refer to a file on disk (file://) from which a URL will be read; an env var (env://) from which the URL will be read; or a direct database URL.`,
	})

	return set
}

func (c *MigrateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *MigrateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *MigrateCommand) Run(args []string) (retCode int) {
	if result := c.ParseFlagsAndConfig(args); result > 0 {
		return result
	}

	if c.configWrapperCleanupFunc != nil {
		defer func() {
			if err := c.configWrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error finalizing config kms: %w", err))
			}
		}()
	}

	dialect := "postgres"

	c.srv = base.NewServer(&base.Command{UI: c.UI})

	if err := c.srv.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	serverName, err := os.Hostname()
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to determine hostname: %w", err).Error())
		return base.CommandCliError
	}
	serverName = fmt.Sprintf("%s/boundary-database-migrate", serverName)
	if err := c.srv.SetupEventing(
		c.srv.Logger,
		c.srv.StderrLock,
		serverName,
		base.WithEventerConfig(c.Config.Eventing)); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	pluginLogger, err := event.NewHclogLogger(c.Context, c.srv.Eventer)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating host catalog plugin logger: %v", err))
		return base.CommandCliError
	}

	_, awsCleanup, err := external_host_plugins.CreateHostPlugin(
		c.Context,
		"aws",
		external_host_plugins.WithPluginOptions(
			pluginutil.WithPluginExecutionDirectory(c.Config.Plugins.ExecutionDir),
			pluginutil.WithPluginsFilesystem(host_plugin_assets.HostPluginPrefix, host_plugin_assets.FileSystem()),
		),
		external_host_plugins.WithLogger(pluginLogger.Named("aws")),
	)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating dynamic host plugin: %w", err).Error())
		c.UI.Warn(base.WrapAtLength(
			"Starting in Boundary 0.7.0, plugins are being introduced for " +
				"various parts of the system. These plugins are created by writing " +
				"out and executing plugin binaries. The migration function performed " +
				"a check to ensure this system is capable of running plugins and " +
				"encountered an error. The ability to run plugins will eventually " +
				"become mandatory (for instance, for KMS implementations), so we are " +
				"ensuring that it's feasible on a given system before migrating the " +
				"database to the new version of Boundary that requires this capability. " +
				"If your temporary directory is not writable and/or you cannot execute " +
				"binaries in that directory, try setting the field " +
				`"execution_dir" in the "plugins" block in the configuration file:`))
		c.UI.Warn(`
plugins {
	execution_dir = <dir>
}
`)
		c.UI.Warn(base.WrapAtLength(
			"Otherwise, please file a bug at " +
				"https://github.com/hashicorp/boundary/issues/new/choose and tell us " +
				"what the error message is, along with details about your environment. " +
				"We are committed to resolving any issues as quickly as possible."))
		return base.CommandCliError
	}
	if err := awsCleanup(); err != nil {
		c.UI.Error(fmt.Errorf("Error running plugin cleanup function: %w", err).Error())
		return base.CommandCliError
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

	if c.Config.Controller == nil {
		c.UI.Error(`"controller" config block not found`)
		return base.CommandUserError
	}

	if c.Config.Controller.Database == nil {
		c.UI.Error(`"controller.database" config block not found`)
		return base.CommandUserError
	}

	var migrationUrlToParse string
	if c.Config.Controller.Database.MigrationUrl != "" {
		migrationUrlToParse = c.Config.Controller.Database.MigrationUrl
	}
	if c.flagMigrationUrl != "" {
		migrationUrlToParse = c.flagMigrationUrl
	}
	// Fallback to using database URL for everything
	if migrationUrlToParse == "" {
		migrationUrlToParse = c.Config.Controller.Database.Url
	}

	if migrationUrlToParse == "" {
		c.UI.Error(base.WrapAtLength(`neither "url" nor "migration_url" correctly set in "database" config block nor was the "migration-url" flag used`))
		return base.CommandUserError
	}

	migrationUrl, err := parseutil.ParsePath(migrationUrlToParse)
	if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
		c.UI.Error(fmt.Errorf("Error parsing migration url: %w", err).Error())
		return base.CommandUserError
	}

	clean, errCode := migrateDatabase(c.Context, c.UI, dialect, migrationUrl, true, c.Config.Controller.Database.MaxOpenConnections)
	defer clean()
	if errCode != 0 {
		return errCode
	}

	return base.CommandSuccess
}

func (c *MigrateCommand) ParseFlagsAndConfig(args []string) int {
	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	// Validation
	switch {
	case len(c.flagConfig) == 0:
		c.UI.Error("Must specify a config file using -config")
		return base.CommandUserError
	}

	wrapperPath := c.flagConfig
	if c.flagConfigKms != "" {
		wrapperPath = c.flagConfigKms
	}
	wrapper, cleanupFunc, err := wrapper.GetWrapperFromPath(
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
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if wrapper != nil {
		c.configWrapperCleanupFunc = cleanupFunc
		if ifWrapper, ok := wrapper.(wrapping.InitFinalizer); ok {
			if err := ifWrapper.Init(c.Context); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
				c.UI.Error(fmt.Errorf("Could not initialize kms: %w", err).Error())
				return base.CommandUserError
			}
			c.configWrapperCleanupFunc = func() error {
				if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
					c.UI.Warn(fmt.Errorf("Could not finalize kms: %w", err).Error())
				}
				if cleanupFunc != nil {
					return cleanupFunc()
				}
				return nil
			}
		}
	}

	c.Config, err = config.LoadFile(c.flagConfig, wrapper)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return base.CommandUserError
	}

	return base.CommandSuccess
}
