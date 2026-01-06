// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
)

// migrateDatabase updates the schema to the most recent version known by the binary.
// It owns the reporting to the UI any errors.
// We expect the database already to be initialized iff initialized is set to true.
// Returns a cleanup function which must be called even if an error is returned and
// an error code where a non-zero value indicates an error happened.
func migrateDatabase(ctx context.Context, ui cli.Ui, dialect, u string, initialized bool, maxOpenConns int, selectedRepairs schema.RepairMigrations) (func(), int) {
	noop := func() {}
	// This database is used to keep an exclusive lock on the database for the
	// remainder of the command
	dBase, err := common.SqlOpen(dialect, u)
	if err != nil {
		ui.Error(fmt.Errorf("Error establishing db connection: %w", err).Error())
		return noop, 2
	}
	dBase.SetMaxOpenConns(maxOpenConns)
	if err := dBase.PingContext(ctx); err != nil {
		ui.Error(fmt.Sprintf("Unable to connect to the database at %q", u))
		return noop, 2
	}
	man, err := schema.NewManager(ctx, schema.Dialect(dialect), dBase, schema.WithRepairMigrations(selectedRepairs))
	if err != nil {
		if errors.Match(errors.T(errors.MigrationLock), err) {
			ui.Error("Unable to capture a lock on the database.")
		} else {
			ui.Error(fmt.Errorf("Error setting up schema manager: %w", err).Error())
		}
		return noop, 2
	}
	// This is an advisory lock on the DB which is released when the DB session ends.
	if err := man.ExclusiveLock(ctx); err != nil {
		ui.Error("Unable to capture a lock on the database.")
		_ = man.Close(ctx)
		return noop, 2
	}
	unlock := func() {
		// We don't report anything since this should resolve itself anyways.
		_ = man.ExclusiveUnlock(ctx)
		_ = man.Close(ctx)
	}

	st, err := man.CurrentState(ctx)
	if err != nil {
		ui.Error(fmt.Errorf("Error getting database state: %w", err).Error())
		return unlock, 2
	}
	if initialized && !st.Initialized {
		ui.Output(base.WrapAtLength("Database has not been initialized. Please use 'boundary database init' to initialize the boundary database."))
		return unlock, -1
	}
	if !initialized && st.Initialized {
		ui.Output(base.WrapAtLength("Database has already been initialized. Please use 'boundary database migrate' for any upgrade needs."))
		return unlock, -1
	}
	repairLogs, err := man.ApplyMigrations(ctx)
	if err != nil {
		ui.Error(fmt.Errorf("Error running database migrations: %w", err).Error())
		if checkErr, ok := err.(schema.MigrationCheckError); ok {
			ui.Error(fmt.Errorf("%s", strings.Join(checkErr.Problems, "\n")).Error())
			ui.Error(fmt.Sprintf("To automatically repair, use 'boundary database migrate -repair=%s:%d'. This will: %s", checkErr.Edition, checkErr.Version, checkErr.RepairDescription))
		}
		return unlock, 2
	}
	if base.Format(ui) == "table" {
		ui.Info("Migrations successfully run.")
	}
	if len(repairLogs) > 0 && base.Format(ui) == "table" {
		ui.Info("Migration Repair logs...")
		for _, e := range repairLogs {
			ui.Info(fmt.Sprintf("%s:%d:", e.Edition, e.Version))
			for _, entry := range e.Entry {
				ui.Info(entry)
			}
		}
	}

	logs, err := man.GetMigrationLog(ctx)
	if err != nil {
		ui.Error(fmt.Errorf("Error retrieving database migration logs: %w", err).Error())
		return unlock, 2
	}
	if len(logs) > 0 && base.Format(ui) == "table" {
		ui.Info("Migration Logs...")
		for _, e := range logs {
			ui.Info(e.Entry)
		}
	}
	return unlock, 0
}

type RoleInfo struct {
	RoleId string `json:"scope_id"`
	Name   string `json:"name"`
}

func generateInitialLoginRoleTableOutput(in *RoleInfo) string {
	nonAttributeMap := map[string]any{
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

func generateInitialAuthenticatedUserRoleOutput(in *RoleInfo) string {
	nonAttributeMap := map[string]any{
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
		"Initial authenticated user role information:",
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
	nonAttributeMap := map[string]any{
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
	nonAttributeMap := map[string]any{
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
	nonAttributeMap := map[string]any{
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
	nonAttributeMap := map[string]any{
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
