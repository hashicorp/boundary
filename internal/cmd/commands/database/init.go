package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/wrapper"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*InitCommand)(nil)
	_ cli.CommandAutocomplete = (*InitCommand)(nil)
)

type InitCommand struct {
	*base.Command
	srv *base.Server

	SighupCh   chan struct{}
	ReloadedCh chan struct{}
	SigUSR2Ch  chan struct{}

	Config *config.Config

	configWrapper wrapping.Wrapper

	flagConfig                       string
	flagConfigKms                    string
	flagLogLevel                     string
	flagLogFormat                    string
	flagMigrationUrl                 string
	flagAllowDevMigrations           bool
	flagSkipInitialLoginRoleCreation bool
	flagSkipAuthMethodCreation       bool
	flagSkipScopesCreation           bool
	flagSkipHostResourcesCreation    bool
	flagSkipTargetCreation           bool
}

func (c *InitCommand) Synopsis() string {
	return "Initialize Boundary's database"
}

func (c *InitCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary database init [options]",
		"",
		"  Initialize Boundary's database:",
		"",
		"    $ boundary database init -config=/etc/boundary/controller.hcl",
		"",
		"  Unless told not to via flags, some initial resources will be created, in the following order and in the indicated scopes:",
		"",
		"    Initial Login Role (global)",
		"    Password-Type Auth Method (global)",
		"    Org Scope (global)",
		"      Project Scope (org)",
		"        Static-Type Host Catalog (project)",
		"          Static-Type Host Set",
		"          Static-Type Host",
		"        Target (project)",
		"",
		"  If flags are used to skip any of these resources, any resources that would be created afterwards are also skipped.",
		"",
		"  For a full list of examples, please see the documentation.",
	}) + c.Flags().Help()
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

	f = set.NewFlagSet("Init Options")

	f.BoolVar(&base.BoolVar{
		Name:   "allow-development-migrations",
		Target: &c.flagAllowDevMigrations,
		Usage:  "If set the init will continue even if the schema includes database update steps that may not be supported in the next official release.  Boundary does not provide a rollback mechanism so a backup should be taken independently if needed.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-initial-login-role-creation",
		Target: &c.flagSkipInitialLoginRoleCreation,
		Usage:  "If not set, a default role allowing necessary grants for logging in will not be created as part of initialization. If set, the recovery KMS will be needed to perform any actions.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-auth-method-creation",
		Target: &c.flagSkipAuthMethodCreation,
		Usage:  "If not set, an auth method will not be created as part of initialization. If set, the recovery KMS will be needed to perform any actions.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-scopes-creation",
		Target: &c.flagSkipScopesCreation,
		Usage:  "If not set, scopes will not be created as part of initialization.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-host-resources-creation",
		Target: &c.flagSkipHostResourcesCreation,
		Usage:  "If not set, host resources (host catalog, host set, host) will not be created as part of initialization.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-target-creation",
		Target: &c.flagSkipTargetCreation,
		Usage:  "If not set, a target will not be created as part of initialization.",
	})

	f.StringVar(&base.StringVar{
		Name:   "migration-url",
		Target: &c.flagMigrationUrl,
		Usage:  `If set, overrides a migration URL set in config, and specifies the URL used to connect to the database for initialization. This can allow different permissions for the user running initialization vs. normal operation. This can refer to a file on disk (file://) from which a URL will be read; an env var (env://) from which the URL will be read; or a direct database URL.`,
	})

	return set
}

func (c *InitCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *InitCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *InitCommand) Run(args []string) (retCode int) {
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

	if c.Config.Controller == nil {
		c.UI.Error(`"controller" config block not found`)
		return 1
	}

	if c.Config.Controller.Database == nil {
		c.UI.Error(`"controller.database" config block not found`)
		return 1
	}

	urlToParse := c.Config.Controller.Database.Url
	if urlToParse == "" {
		c.UI.Error(`"url" not specified in "database" config block"`)
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
		migrationUrlToParse = urlToParse
	}

	dbaseUrl, err := config.ParseAddress(urlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
		return 1
	}

	// This database is used to keep an exclusive lock on the database for the
	// remainder of the command
	dBase, err := sql.Open(dialect, dbaseUrl)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error establishing db connection for locking: %w", err).Error())
		return 1
	}
	man, err := schema.NewManager(c.Context, dialect, dBase)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error setting up schema manager for locking: %w", err).Error())
		return 1
	}
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
		if st.InitializationStarted {
			// TODO: Separate from the "dirty" bit maintained by the schema
			//  manager maintain a bit which indicates that this full command
			//  was completed successfully (with all default resources being created).
			//  Use that bit to determine if a previous init was completed
			//  successfully or not.
			c.UI.Error(base.WrapAtLength("Database was already been " +
				"initialized. If the initialization did not complete successfully " +
				"please revert the database to it's fresh state."))
			return 1
		}
	}

	// This is an advisory locks on the DB which is released when the db session ends.
	if err := man.ExclusiveLock(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error capturing an exclusive lock: %w", err).Error())
		return 1
	}

	migrationUrl, err := config.ParseAddress(migrationUrlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing migration url: %w", err).Error())
		return 1
	}

	// Core migrations using the migration URL
	{
		migrationUrl = strings.TrimSpace(migrationUrl)
		ran, err := schema.InitStore(c.Context, dialect, migrationUrl)
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
	if err := c.srv.ConnectToDatabase(dialect); err != nil {
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

	var jsonMap map[string]interface{}
	if base.Format(c.UI) == "json" {
		jsonMap = make(map[string]interface{})
		defer func() {
			b, err := base.JsonFormatter{}.Format(jsonMap)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				retCode = 1
				return
			}
			c.UI.Output(string(b))
		}()
	}

	if c.flagSkipInitialLoginRoleCreation {
		return 0
	}

	role, err := c.srv.CreateInitialLoginRole(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial global-scoped login role: %w", err).Error())
		return 1
	}

	roleInfo := &RoleInfo{
		RoleId: role.PublicId,
		Name:   role.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialRoleTableOutput(roleInfo))
	case "json":
		jsonMap["login_role"] = roleInfo
	}

	if c.flagSkipAuthMethodCreation {
		return 0
	}

	// Use an easy name, at least
	c.srv.DevLoginName = "admin"
	am, user, err := c.srv.CreateInitialAuthMethod(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial auth method and user: %w", err).Error())
		return 1
	}

	authMethodInfo := &AuthInfo{
		AuthMethodId:   c.srv.DevAuthMethodId,
		AuthMethodName: am.Name,
		LoginName:      c.srv.DevLoginName,
		Password:       c.srv.DevPassword,
		ScopeId:        scope.Global.String(),
		UserId:         c.srv.DevUserId,
		UserName:       user.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialAuthTableOutput(authMethodInfo))
	case "json":
		jsonMap["auth_method"] = authMethodInfo
	}

	if c.flagSkipScopesCreation {
		return 0
	}

	orgScope, projScope, err := c.srv.CreateInitialScopes(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial scopes: %w", err).Error())
		return 1
	}

	orgScopeInfo := &ScopeInfo{
		ScopeId: c.srv.DevOrgId,
		Type:    scope.Org.String(),
		Name:    orgScope.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialScopeTableOutput(orgScopeInfo))
	case "json":
		jsonMap["org_scope"] = orgScopeInfo
	}

	projScopeInfo := &ScopeInfo{
		ScopeId: c.srv.DevProjectId,
		Type:    scope.Project.String(),
		Name:    projScope.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialScopeTableOutput(projScopeInfo))
	case "json":
		jsonMap["proj_scope"] = projScopeInfo
	}

	if c.flagSkipHostResourcesCreation {
		return 0
	}

	hc, hs, h, err := c.srv.CreateInitialHostResources(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial host resources: %w", err).Error())
		return 1
	}

	hostInfo := &HostInfo{
		HostCatalogId:   c.srv.DevHostCatalogId,
		HostCatalogName: hc.GetName(),
		HostSetId:       c.srv.DevHostSetId,
		HostSetName:     hs.GetName(),
		HostId:          c.srv.DevHostId,
		HostName:        h.GetName(),
		Type:            "static",
		ScopeId:         c.srv.DevProjectId,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialHostResourcesTableOutput(hostInfo))
	case "json":
		jsonMap["host_resources"] = hostInfo
	}

	if c.flagSkipTargetCreation {
		return 0
	}

	c.srv.DevTargetSessionConnectionLimit = -1
	t, err := c.srv.CreateInitialTarget(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial target: %w", err).Error())
		return 1
	}

	targetInfo := &TargetInfo{
		TargetId:               c.srv.DevTargetId,
		DefaultPort:            t.GetDefaultPort(),
		SessionMaxSeconds:      t.GetSessionMaxSeconds(),
		SessionConnectionLimit: t.GetSessionConnectionLimit(),
		Type:                   "tcp",
		ScopeId:                c.srv.DevProjectId,
		Name:                   t.GetName(),
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialTargetTableOutput(targetInfo))
	case "json":
		jsonMap["target"] = targetInfo
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
