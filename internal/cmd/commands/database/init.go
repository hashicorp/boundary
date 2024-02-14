// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*InitCommand)(nil)
	_ cli.CommandAutocomplete = (*InitCommand)(nil)
)

type InitCommand struct {
	*base.Server

	SighupCh   chan struct{}
	ReloadedCh chan struct{}
	SigUSR2Ch  chan struct{}

	Config *config.Config

	// This will be intialized, if needed, in ParseFlagsAndConfig when
	// instantiating a config wrapper, if requested. It's then called as a
	// deferred function on the Run method.
	configWrapperCleanupFunc func() error

	flagConfig                                   []string
	flagConfigKms                                string
	flagLogLevel                                 string
	flagLogFormat                                string
	flagMigrationUrl                             string
	flagSkipInitialLoginRoleCreation             bool
	flagSkipInitialAuthenticatedUserRoleCreation bool
	flagSkipAuthMethodCreation                   bool
	flagSkipScopesCreation                       bool
	flagSkipHostResourcesCreation                bool
	flagSkipTargetCreation                       bool
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
	set := c.FlagSet(base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

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

	f = set.NewFlagSet("Init Options")

	f.BoolVar(&base.BoolVar{
		Name:   "skip-initial-login-role-creation",
		Target: &c.flagSkipInitialLoginRoleCreation,
		Usage:  "If set, a role providing necessary grants for logging in will not be created as part of initialization. If set, the recovery KMS will be needed to perform any actions.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-initial-authenticated-user-role-creation",
		Target: &c.flagSkipInitialAuthenticatedUserRoleCreation,
		Usage:  "If set, a role providing initial grants for any authenticated user will not be created as part of initialization.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-auth-method-creation",
		Target: &c.flagSkipAuthMethodCreation,
		Usage:  "If set, an auth method will not be created as part of initialization. If set, the recovery KMS will be needed to perform any actions.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-scopes-creation",
		Target: &c.flagSkipScopesCreation,
		Usage:  "If set, scopes will not be created as part of initialization.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-host-resources-creation",
		Target: &c.flagSkipHostResourcesCreation,
		Usage:  "If set, host resources (host catalog, host set, host) will not be created as part of initialization.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "skip-target-creation",
		Target: &c.flagSkipTargetCreation,
		Usage:  "If set, a target will not be created as part of initialization.",
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

	defer func() {
		if err := c.RunShutdownFuncs(); err != nil {
			c.UI.Error(fmt.Errorf("Error running shutdown tasks: %w", err).Error())
		}
	}()

	if c.configWrapperCleanupFunc != nil {
		defer func() {
			if err := c.configWrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error finalizing config kms: %w", err))
			}
		}()
	}

	dialect := "postgres"

	if err := c.SetupLogging(c.flagLogLevel, c.flagLogFormat, c.Config.LogLevel, c.Config.LogFormat); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	serverName, err := os.Hostname()
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to determine hostname: %w", err).Error())
		return base.CommandCliError
	}
	serverName = fmt.Sprintf("%s/boundary-database-init", serverName)
	if err := c.SetupEventing(c.Context, c.Logger, c.StderrLock, serverName, base.WithEventerConfig(c.Config.Eventing)); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	if err := c.SetupKMSes(c.Context, c.UI, c.Config); err != nil {
		c.UI.Error(err.Error())
		return base.CommandCliError
	}

	if c.RootKms == nil {
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

	c.DatabaseMaxOpenConnections = c.Config.Controller.Database.MaxOpenConnections

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

	clean, errCode := migrateDatabase(c.Context, c.UI, dialect, migrationUrl, false, c.DatabaseMaxOpenConnections, nil)
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
	c.DatabaseUrl, err = parseutil.ParsePath(urlToParse)
	if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
		c.UI.Error(fmt.Errorf("Error parsing database url: %w", err).Error())
		return base.CommandUserError
	}
	// Everything after is done with normal database URL and is affecting actual data
	if err := c.OpenAndSetServerDatabase(c.Context, dialect); err != nil {
		c.UI.Error(fmt.Errorf("Error connecting to database after migrations: %w", err).Error())
		return base.CommandCliError
	}
	if err := c.verifyOplogIsEmpty(c.Context); err != nil {
		c.UI.Error(fmt.Sprintf("The database appears to have already been initialized: %v", err))
		return base.CommandCliError
	}
	if err := c.CreateGlobalKmsKeys(c.Context); err != nil {
		c.UI.Error(fmt.Errorf("Error creating global-scope KMS keys: %w", err).Error())
		return base.CommandCliError
	}

	if base.Format(c.UI) == "table" {
		c.UI.Info("Global-scope KMS keys successfully created.")
	}

	var jsonMap map[string]any
	if base.Format(c.UI) == "json" {
		jsonMap = make(map[string]any)
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

	role, err := c.CreateInitialLoginRole(c.Context)
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
		c.UI.Output(generateInitialLoginRoleTableOutput(roleInfo))
	case "json":
		jsonMap["login_role"] = roleInfo
	}

	if c.flagSkipInitialAuthenticatedUserRoleCreation {
		return base.CommandSuccess
	}

	role, err = c.CreateInitialAuthenticatedUserRole(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial global-scoped authenticated user role: %w", err).Error())
		return base.CommandCliError
	}

	roleInfo = &RoleInfo{
		RoleId: role.PublicId,
		Name:   role.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialAuthenticatedUserRoleOutput(roleInfo))
	case "json":
		jsonMap["authenticated_user_role"] = roleInfo
	}

	if c.flagSkipAuthMethodCreation {
		return base.CommandSuccess
	}

	// Use an easy name, at least
	c.DevLoginName = "admin"
	am, user, err := c.CreateInitialPasswordAuthMethod(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial auth method and user: %w", err).Error())
		return base.CommandCliError
	}

	authMethodInfo := &AuthInfo{
		AuthMethodId:   c.DevPasswordAuthMethodId,
		AuthMethodName: am.Name,
		LoginName:      c.DevLoginName,
		Password:       c.DevPassword,
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

	orgScope, projScope, err := c.CreateInitialScopes(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial scopes: %w", err).Error())
		return base.CommandCliError
	}

	orgScopeInfo := &ScopeInfo{
		ScopeId: c.DevOrgId,
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
		ScopeId: c.DevProjectId,
		Type:    scope.Project.String(),
		Name:    projScope.Name,
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialScopeTableOutput(projScopeInfo))
	case "json":
		jsonMap["project_scope"] = projScopeInfo
	}

	if c.flagSkipHostResourcesCreation {
		return base.CommandSuccess
	}

	hc, hs, h, err := c.CreateInitialHostResources(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial host resources: %w", err).Error())
		return base.CommandCliError
	}

	hostInfo := &HostInfo{
		HostCatalogId:   c.DevHostCatalogId,
		HostCatalogName: hc.GetName(),
		HostSetId:       c.DevHostSetId,
		HostSetName:     hs.GetName(),
		HostId:          c.DevHostId,
		HostName:        h.GetName(),
		Type:            "static",
		ScopeId:         c.DevProjectId,
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

	c.DevTargetSessionConnectionLimit = -1
	ta, err := c.CreateInitialTargetWithAddress(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial target: %w", err).Error())
		return base.CommandCliError
	}
	taInfo := &TargetInfo{
		TargetId:               ta.GetPublicId(),
		DefaultPort:            ta.GetDefaultPort(),
		SessionMaxSeconds:      ta.GetSessionMaxSeconds(),
		SessionConnectionLimit: ta.GetSessionConnectionLimit(),
		Type:                   string(ta.GetType()),
		ScopeId:                ta.GetProjectId(),
		Name:                   ta.GetName(),
	}

	ths, err := c.CreateInitialTargetWithHostSources(c.Context)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating initial secondary target: %w", err).Error())
		return base.CommandCliError
	}
	thsInfo := &TargetInfo{
		TargetId:               ths.GetPublicId(),
		DefaultPort:            ths.GetDefaultPort(),
		SessionMaxSeconds:      ths.GetSessionMaxSeconds(),
		SessionConnectionLimit: ths.GetSessionConnectionLimit(),
		Type:                   string(ths.GetType()),
		ScopeId:                ths.GetProjectId(),
		Name:                   ths.GetName(),
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateInitialTargetTableOutput(taInfo))
		c.UI.Output(generateInitialTargetTableOutput(thsInfo))
	case "json":
		jsonMap["target"] = taInfo
		jsonMap["target_secondary"] = thsInfo
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

	c.Config, err = config.Load(c.Context, c.flagConfig, c.flagConfigKms)
	if err != nil {
		c.UI.Error("Error parsing config: " + err.Error())
		return base.CommandUserError
	}

	return base.CommandSuccess
}

func (c *InitCommand) verifyOplogIsEmpty(ctx context.Context) error {
	const op = "database.(InitCommand).verifyOplogIsEmpty"
	underlyingDB, err := c.Database.SqlDB(ctx)
	if err != nil {
		return errors.New(ctx, errors.Internal, op, "unable to retrieve db", errors.WithWrap(err))
	}
	r := underlyingDB.QueryRowContext(c.Context, "select not exists(select 1 from oplog_entry limit 1)")
	if r.Err() != nil {
		return r.Err()
	}
	var empty bool
	if err := r.Scan(&empty); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if !empty {
		return errors.New(ctx, errors.MigrationIntegrity, op, "oplog_entry is not empty")
	}
	return nil
}
