package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/wrapper"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*InitCommand)(nil)
var _ cli.CommandAutocomplete = (*InitCommand)(nil)

type InitCommand struct {
	*base.Command
	srv *base.Server

	SighupCh      chan struct{}
	childSighupCh []chan struct{}
	ReloadedCh    chan struct{}
	SigUSR2Ch     chan struct{}

	Config     *config.Config
	controller *controller.Controller

	configWrapper wrapping.Wrapper

	flagConfig                 string
	flagConfigKms              string
	flagLogLevel               string
	flagLogFormat              string
	flagMigrationUrl           string
	flagSkipAuthMethodCreation bool
}

func (c *InitCommand) Synopsis() string {
	return "Initialize Boundary's database"
}

func (c *InitCommand) Help() string {
	helpText := `
Usage: boundary database init [options]

  Initialize Boundary's database:

      $ boundary database init -config=/etc/boundary/controller.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *InitCommand) Flags() *base.FlagSets {
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

	f = set.NewFlagSet("Init Options")

	f.BoolVar(&base.BoolVar{
		Name:   "skip-auth-method-creation",
		Target: &c.flagSkipAuthMethodCreation,
		Usage:  "If not set, an auth method will not be created as part of initialization. If set, the recovery KMS will be needed to perform any actions.",
	})

	f.StringVar(&base.StringVar{
		Name:    "migration-url",
		Target:  &c.flagMigrationUrl,
		Default: base.NotSetValue,
		Usage:   `If set, overrides a migration URL set in config, and specifies the URL used to connect to the database for initialization. This can allow different permissions for the user running initialization vs. normal operation. This can refer to a file on disk (file://) from which a URL will be read; an env var (env://) from which the URL will be read; or a direct database URL.`,
	})

	return set
}

func (c *InitCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *InitCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *InitCommand) Run(args []string) int {
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

	c.srv = base.NewServer(&base.Command{UI: c.UI})

	if err := c.srv.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if err := c.srv.SetupKMSes(c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.srv.RootKms == nil {
		c.UI.Error("Root KMS not found after parsing KMS blocks")
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

	if c.Config.Database == nil {
		c.UI.Error(`"database" config block not found`)
		return 1
	}

	urlToParse := c.Config.Database.Url
	if urlToParse == "" {
		c.UI.Error(`"url" not specified in "database" config block"`)
		return 1
	}

	var migrationUrlToParse string
	if c.Config.Database.MigrationUrl != "" {
		migrationUrlToParse = c.Config.Database.MigrationUrl
	}
	if c.flagMigrationUrl != "" && c.flagMigrationUrl != base.NotSetValue {
		migrationUrlToParse = c.flagMigrationUrl
	}
	// Fallback to using database URL for everything
	if migrationUrlToParse == "" {
		migrationUrlToParse = urlToParse
	}

	dbaseUrl, err := config.ParseAddress(urlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
		return 1
	}

	migrationUrl, err := config.ParseAddress(migrationUrlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing migration url: %w", err).Error())
		return 1
	}

	// Core migrations using the migration URL
	{
		c.srv.DatabaseUrl = strings.TrimSpace(migrationUrl)
		ldb, err := sql.Open("postgres", c.srv.DatabaseUrl)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error opening database to check init status: %w", err).Error())
			return 1
		}
		_, err = ldb.QueryContext(c.Context, "select version from schema_migrations")
		switch {
		case err == nil:
			if base.Format(c.UI) == "table" {
				c.UI.Info("Database already initialized.")
				return 0
			}
		case strings.Contains(err.Error(), "does not exist"):
			// Doesn't exist so we continue on
		default:
			c.UI.Error(fmt.Errorf("Error querying database for init status: %w", err).Error())
			return 1
		}
		ran, err := db.InitStore("postgres", nil, c.srv.DatabaseUrl)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error running database migrations: %w", err).Error())
			return 1
		}
		if !ran {
			if base.Format(c.UI) == "table" {
				c.UI.Info("Database already initialized.")
				return 0
			}
		}
		if base.Format(c.UI) == "table" {
			c.UI.Info("Migrations successfully run.")
		}
	}

	// Everything after is done with normal database URL and is affecting actual data
	c.srv.DatabaseUrl = strings.TrimSpace(dbaseUrl)
	if err := c.srv.ConnectToDatabase("postgres"); err != nil {
		c.UI.Error(fmt.Errorf("Error connecting to database after migrations: %w", err).Error())
		return 1
	}
	if err := c.srv.CreateGlobalKmsKeys(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error creating global-scope KMS keys: %w", err).Error())
		return 1
	}

	if base.Format(c.UI) == "table" {
		c.UI.Info("Global-scope KMS keys successfully created.")
	}

	if c.flagSkipAuthMethodCreation {
		return 0
	}

	// Use an easy name, at least
	c.srv.DevLoginName = "admin"
	if err := c.srv.CreateInitialAuthMethod(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial auth method and user: %w", err).Error())
		return 1
	}

	authMethodInfo := &AuthMethodInfo{
		AuthMethodId: c.srv.DevAuthMethodId,
		LoginName:    c.srv.DevLoginName,
		Password:     c.srv.DevPassword,
		ScopeId:      scope.Global.String(),
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialAuthMethodTableOutput(authMethodInfo))
	case "json":
		b, err := base.JsonFormatter{}.Format(authMethodInfo)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}

func (c *InitCommand) ParseFlagsAndConfig(args []string) int {
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
	switch {
	case len(c.flagConfig) == 0:
		c.UI.Error("Must specify a config file using -config")
		return 1
	}

	c.Config, err = config.LoadFile(c.flagConfig, wrapper)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return 1
	}

	return 0
}
