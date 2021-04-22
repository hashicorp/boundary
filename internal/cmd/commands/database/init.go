package database

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
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

	c.srv = base.NewServer(&base.Command{UI: c.UI})

	if err := c.srv.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	if err := c.srv.SetupKMSes(c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	if c.srv.RootKms == nil {
		c.UI.Error("Root KMS not found after parsing KMS blocks")
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

	migrationUrl, err := config.ParseAddress(migrationUrlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing migration url: %w", err).Error())
		return base.CommandUserError
	}

	clean, errCode := migrateDatabase(c.Context, c.UI, dialect, migrationUrl, true)
	defer clean()
	switch errCode {
	case 0:
	case -1:
		return 0
	default:
		return errCode
	}

	urlToParse := c.Config.Controller.Database.Url
	if urlToParse == "" {
		c.UI.Error(`"url" not specified in "database" config block`)
		return base.CommandUserError
	}
	c.srv.DatabaseUrl, err = config.ParseAddress(urlToParse)
	if err != nil && err != config.ErrNotAUrl {
		c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
		return base.CommandUserError
	}
	// Everything after is done with normal database URL and is affecting actual data
	if err := c.srv.ConnectToDatabase(dialect); err != nil {
		c.UI.Error(fmt.Errorf("Error connecting to database after migrations: %w", err).Error())
		return base.CommandCliError
	}
	if err := c.verifyOplogIsEmpty(); err != nil {
		c.UI.Error(fmt.Sprintf("The database appears to have already been initialized: %v", err))
		return base.CommandCliError
	}
	if err := c.srv.CreateGlobalKmsKeys(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error creating global-scope KMS keys: %w", err).Error())
		return base.CommandCliError
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
				retCode = 2
				return
			}
			c.UI.Output(string(b))
		}()
	}

	if c.flagSkipInitialLoginRoleCreation {
		return base.CommandSuccess
	}

	role, err := c.srv.CreateInitialLoginRole(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial global-scoped login role: %w", err).Error())
		return base.CommandCliError
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
		return base.CommandSuccess
	}

	// Use an easy name, at least
	c.srv.DevLoginName = "admin"
	am, user, err := c.srv.CreateInitialPasswordAuthMethod(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial auth method and user: %w", err).Error())
		return base.CommandCliError
	}

	authMethodInfo := &AuthInfo{
		AuthMethodId:   c.srv.DevPasswordAuthMethodId,
		AuthMethodName: am.Name,
		LoginName:      c.srv.DevLoginName,
		Password:       c.srv.DevPassword,
		ScopeId:        scope.Global.String(),
		UserId:         user.PublicId,
		UserName:       user.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialAuthTableOutput(authMethodInfo))
	case "json":
		jsonMap["auth_method"] = authMethodInfo
	}

	if c.flagSkipScopesCreation {
		return base.CommandSuccess
	}

	orgScope, projScope, err := c.srv.CreateInitialScopes(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial scopes: %w", err).Error())
		return base.CommandCliError
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
		return base.CommandSuccess
	}

	hc, hs, h, err := c.srv.CreateInitialHostResources(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial host resources: %w", err).Error())
		return base.CommandCliError
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
		return base.CommandSuccess
	}

	c.srv.DevTargetSessionConnectionLimit = -1
	t, err := c.srv.CreateInitialTarget(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial target: %w", err).Error())
		return base.CommandCliError
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

	return base.CommandSuccess
}

func (c *InitCommand) ParseFlagsAndConfig(args []string) int {
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
	wrapper, err := wrapper.GetWrapperFromPath(wrapperPath, "config")
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if wrapper != nil {
		c.configWrapper = wrapper
		if err := wrapper.Init(c.Context); err != nil {
			c.UI.Error(fmt.Errorf("Could not initialize kms: %w", err).Error())
			return base.CommandUserError
		}
	}

	c.Config, err = config.LoadFile(c.flagConfig, wrapper)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return base.CommandUserError
	}

	return base.CommandSuccess
}

func (c *InitCommand) verifyOplogIsEmpty() error {
	const op = "database.(InitCommand).verifyOplogIsEmpty"
	r := c.srv.Database.DB().QueryRowContext(c.Context, "select not exists(select 1 from oplog_entry limit 1)")
	if r.Err() != nil {
		return r.Err()
	}
	var empty bool
	r.Scan(&empty)
	if !empty {
		return errors.New(errors.MigrationIntegrity, op, "oplog_entry is not empty")
	}
	return nil
}
