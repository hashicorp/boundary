package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
)

// migrateDatabase updates the schema to the most recent version known by the binary.
// It owns the reporting to the UI any errors.
// Returns a cleanup function which must be called even if an error is returned and
// an error code where a non-zero value indicates an error happened.
func migrateDatabase(ctx context.Context, ui cli.Ui, dialect, u string, requireFresh bool) (func(), int) {
	noop := func() {}
	// This database is used to keep an exclusive lock on the database for the
	// remainder of the command
	dBase, err := sql.Open(dialect, u)
	if err != nil {
		ui.Error(fmt.Errorf("Error establishing db connection: %w", err).Error())
		return noop, 1
	}
	if err := dBase.PingContext(ctx); err != nil {
		ui.Error(fmt.Sprintf("Unable to connect to the database at %q", u))
		return noop, 1
	}
	man, err := schema.NewManager(ctx, dialect, dBase)
	if err != nil {
		if errors.Match(errors.T(errors.MigrationLock), err) {
			ui.Error("Unable to capture a lock on the database.")
		} else {
			ui.Error(fmt.Errorf("Error setting up schema manager: %w", err).Error())
		}
		return noop, 1
	}
	// This is an advisory lock on the DB which is released when the DB session ends.
	if err := man.ExclusiveLock(ctx); err != nil {
		ui.Error("Unable to capture a lock on the database.")
		return noop, 1
	}
	unlock := func() {
		// We don't report anything since this should resolve itself anyways.
		_ = man.ExclusiveUnlock(ctx)
	}

	st, err := man.CurrentState(ctx)
	if err != nil {
		ui.Error(fmt.Errorf("Error getting database state: %w", err).Error())
		return unlock, 1
	}
	if requireFresh && st.InitializationStarted {
		ui.Error(base.WrapAtLength("Database has already been initialized.  Please use 'boundary database migrate'."))
		return unlock, 1
	}
	if st.Dirty {
		ui.Error(base.WrapAtLength("Database is in a bad state.  Please revert back to the last known good state."))
		return unlock, 1
	}
	if err := man.RollForward(ctx); err != nil {
		ui.Error(fmt.Errorf("Error running database migrations: %w", err).Error())
		return unlock, 1
	}
	if base.Format(ui) == "table" {
		ui.Info("Migrations successfully run.")
	}
	return unlock, 0
}

type RoleInfo struct {
	RoleId string `json:"scope_id"`
	Name   string `json:"name"`
}

func generateInitialRoleTableOutput(in *RoleInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Role ID": in.RoleId,
		"Name":    in.Name,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial login role information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type AuthInfo struct {
	AuthMethodId   string `json:"auth_method_id"`
	AuthMethodName string `json:"auth_method_name"`
	LoginName      string `json:"login_name"`
	Password       string `json:"password"`
	ScopeId        string `json:"scope_id"`
	UserId         string `json:"user_id"`
	UserName       string `json:"user_name"`
}

func generateInitialAuthTableOutput(in *AuthInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID":         in.ScopeId,
		"Auth Method ID":   in.AuthMethodId,
		"Auth Method Name": in.AuthMethodName,
		"Login Name":       in.LoginName,
		"Password":         in.Password,
		"User ID":          in.UserId,
		"User Name":        in.UserName,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial auth information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type ScopeInfo struct {
	ScopeId string `json:"scope_id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
}

func generateInitialScopeTableOutput(in *ScopeInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Scope ID": in.ScopeId,
		"Type":     in.Type,
		"Name":     in.Name,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		fmt.Sprintf("Initial %s scope information:", in.Type),
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type HostInfo struct {
	HostCatalogId   string `json:"host_catalog_id"`
	HostSetId       string `json:"host_set_id"`
	HostId          string `json:"host_id"`
	Type            string `json:"type"`
	ScopeId         string `json:"scope_id"`
	HostCatalogName string `json:"host_catalog_name"`
	HostSetName     string `json:"host_set_name"`
	HostName        string `json:"host_name"`
}

func generateInitialHostResourcesTableOutput(in *HostInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Host Catalog ID":   in.HostCatalogId,
		"Host Catalog Name": in.HostCatalogName,
		"Host Set ID":       in.HostSetId,
		"Host Set Name":     in.HostSetName,
		"Host ID":           in.HostId,
		"Host Name":         in.HostName,
		"Type":              in.Type,
		"Scope ID":          in.ScopeId,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial host resources information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}

type TargetInfo struct {
	TargetId               string `json:"target_id"`
	DefaultPort            uint32 `json:"default_port"`
	SessionMaxSeconds      uint32 `json:"session_max_seconds"`
	SessionConnectionLimit int32  `json:"session_connection_limit"`
	Type                   string `json:"type"`
	ScopeId                string `json:"scope_id"`
	Name                   string `json:"name"`
}

func generateInitialTargetTableOutput(in *TargetInfo) string {
	nonAttributeMap := map[string]interface{}{
		"Target ID":                in.TargetId,
		"Default Port":             in.DefaultPort,
		"Session Max Seconds":      in.SessionMaxSeconds,
		"Session Connection Limit": in.SessionConnectionLimit,
		"Type":                     in.Type,
		"Scope ID":                 in.ScopeId,
		"Name":                     in.Name,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret := []string{
		"",
		"Initial target information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	return base.WrapForHelpText(ret)
}
