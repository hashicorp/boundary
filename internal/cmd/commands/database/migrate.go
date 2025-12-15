// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	boundary_plugin_assets "github.com/hashicorp/boundary/plugins/boundary"
	external_plugins "github.com/hashicorp/boundary/sdk/plugins"
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

	selectedRepairs schema.RepairMigrations

	flagConfig             []string
	flagConfigKms          string
	flagLogLevel           string
	flagLogFormat          string
	flagMigrationUrl       string
	flagRepairMigrations   []string
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

	f.StringSliceVar(&base.StringSliceVar{
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

	f.StringSliceVar(&base.StringSliceVar{
		Name:   "repair",
		Target: &c.flagRepairMigrations,
		Usage:  `Run the repair function for the provided migration version.`,
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
		c.Context,
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

	_, plgCleanup, err := external_plugins.CreateHostPlugin(
		c.Context,
		"azure",
		external_plugins.WithPluginOptions(
			pluginutil.WithPluginExecutionDirectory(c.Config.Plugins.ExecutionDir),
			pluginutil.WithPluginsFilesystem(boundary_plugin_assets.PluginPrefix, boundary_plugin_assets.FileSystem()),
		),
		external_plugins.WithLogger(pluginLogger.Named("azure")),
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
	if err := plgCleanup(); err != nil {
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
				"systems where this call is supported. If you are running Boundary " +
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

	clean, errCode := migrateDatabase(
		c.Context,
		c.UI,
		dialect,
		migrationUrl,
		true,
		c.Config.Controller.Database.MaxOpenConnections,
		c.selectedRepairs,
	)
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

	c.selectedRepairs = make(schema.RepairMigrations)
	for _, r := range c.flagRepairMigrations {
		parts := strings.SplitN(r, ":", 2)
		if len(parts) != 2 {
			c.UI.Error(fmt.Sprintf("Error parsing repair option, invalid format: %s", r))
			return base.CommandUserError
		}

		edition := parts[0]
		version, err := strconv.Atoi(parts[1])
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing repair option %s, %s", r, err.Error()))
			return base.CommandUserError
		}

		c.selectedRepairs.Add(edition, version)
	}

	// Validation
	switch {
	case len(c.flagConfig) == 0:
		c.UI.Error("Must specify a config file using -config")
		return base.CommandUserError
	}

	c.Config, err = config.Load(c.Context, c.flagConfig, c.flagConfigKms)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return base.CommandUserError
	}

	return base.CommandSuccess
}
