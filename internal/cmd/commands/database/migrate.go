package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/sdk/wrapper"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/mlock"
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

	configWrapper wrapping.Wrapper

	flagConfig             string
	flagConfigKms          string
	flagLogLevel           string
	flagLogFormat          string
	flagMigrationUrl       string
	flagAllowDevMigrations bool
}

func (c *MigrateCommand) Synopsis() string {
	return "Initialize Boundary's database"
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

	f.BoolVar(&base.BoolVar{
		Name:   "allow-development-migrations",
		Target: &c.flagAllowDevMigrations,
		Usage:  "If set the migrate command will continue even if the schema includes database update steps that may not be supported in the next official release.  Boundary does not provide a rollback mechanism so a backup should be taken independently if needed.",
	})

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

	if c.configWrapper != nil {
		defer func() {
			if err := c.configWrapper.Finalize(c.Context); err != nil {
				c.UI.Warn(fmt.Errorf("Error finalizing config kms: %w", err).Error())
			}
		}()
	}

	dialect := "postgres"

	if schema.DevMigration(dialect) != c.flagAllowDevMigrations {
		if schema.DevMigration(dialect) {
			c.UI.Error(base.WrapAtLength("This version of the binary has " +
				"dev database schema updates which may not be supported in the " +
				"next official release. To proceed anyways please use the " +
				"'-allow-development-migrations' flag."))
			return 2
		} else {
			c.UI.Error(base.WrapAtLength("The '-allow-development-migrations' " +
				"flag was set but this binary has no dev database schema updates."))
			return 3
		}
	}

	c.srv = base.NewServer(&base.Command{UI: c.UI})

	if err := c.srv.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return 1
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
		return 1
	}

	if c.Config.Controller.Database == nil {
		c.UI.Error(`"controller.database" config block not found`)
		return 1
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
		return 1
	}

	migrationUrl, err := config.ParseAddress(migrationUrlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing migration url: %w", err).Error())
		return 1
	}

	// This database is used to keep an exclusive lock on the database for the
	// remainder of the command
	dBase, err := sql.Open(dialect, migrationUrl)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error establishing db connection for locking: %w", err).Error())
		return 1
	}
	man, err := schema.NewManager(c.Context, dialect, dBase)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error setting up schema manager for locking: %w", err).Error())
		return 1
	}

	// This is an advisory locks on the DB which is released when the db session ends.
	if err := man.ExclusiveLock(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error capturing an exclusive lock: %w", err).Error())
		return 1
	}
	defer func() {
		if err := man.ExclusiveUnlock(c.Context); err != nil {
			c.UI.Error(fmt.Errorf("Unable to release exclusive lock to the database: %w", err).Error())
		}
	}()
	{
		st, err := man.CurrentState(c.Context)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error getting database state: %w", err).Error())
			return 1
		}
		if st.Dirty {
			c.UI.Error(base.WrapAtLength("Database is in a bad initialization " +
				"state.  Please revert back to the last known good state."))
			return 1
		}
		if st.BinarySchemaVersion == st.DatabaseSchemaVersion {
			c.UI.Info(base.WrapAtLength("Database is already up to date."))
			return 0
		}
	}

	// Core migrations using the migration URL
	{
		migrationUrl = strings.TrimSpace(migrationUrl)
		ran, err := schema.MigrateStore(c.Context, dialect, migrationUrl)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error running database migrations: %w", err).Error())
			return 1
		}
		if !ran {
			if base.Format(c.UI) == "table" {
				c.UI.Info("Database is already up to date.")
				return 0
			}
		}
		if base.Format(c.UI) == "table" {
			c.UI.Info("Migrations successfully run.")
		}
	}

	return 0
}

func (c *MigrateCommand) ParseFlagsAndConfig(args []string) int {
	var err error

	f := c.Flags()

	if err = f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Validation
	switch {
	case len(c.flagConfig) == 0:
		c.UI.Error("Must specify a config file using -config")
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

	c.Config, err = config.LoadFile(c.flagConfig, wrapper)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return 1
	}

	return 0
}
