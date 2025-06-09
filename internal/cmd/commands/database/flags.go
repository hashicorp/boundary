// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"fmt"

	"github.com/hashicorp/boundary/version"
)

const (
	flagConfigName                             = "config"
	flagConfigKmsName                          = "config-kms"
	flagLogLevelName                           = "log-level"
	flagLogFormatName                          = "log-format"
	flagSkipInitialLoginRoleName               = "skip-initial-login-role-creation"
	flagSkipInitialAuthenticatedUserRoleName   = "skip-initial-authenticated-user-role-creation"
	flagCreateInitialLoginRoleName             = "create-initial-login-role"
	flagCreateInitialAuthenticatedUserRoleName = "create-initial-authenticated-user-role"
	flagSkipAuthMethodName                     = "skip-auth-method-creation"
	flagSkipScopesName                         = "skip-scopes-creation"
	flagSkipHostResourcesName                  = "skip-host-resources-creation"
	flagSkipTargetName                         = "skip-target-creation"
	flagMigrationUrlName                       = "migration-url"
)

// initFlags contains the flags for the database init command, including optional
// flags to control which initialization steps are skipped and the reasons for skipping.
type initFlags struct {
	flagConfig                                   []string
	flagConfigKms                                string
	flagLogLevel                                 string
	flagLogFormat                                string
	flagMigrationUrl                             string
	flagSkipInitialLoginRoleCreation             bool
	flagSkipInitialAuthenticatedUserRoleCreation bool
	flagCreateInitialLoginRole                   bool
	flagCreateInitialAuthenticatedUserRole       bool
	flagSkipAuthMethodCreation                   bool
	flagSkipScopesCreation                       bool
	flagSkipHostResourcesCreation                bool
	flagSkipTargetCreation                       bool
}

// SkipInitialLoginRoleCreation checks if the creation of the initial anonymous login role should be skipped.
// It returns a boolean indicating whether to skip and a reason string if skipping is applicable.
//
// The creation of the initial login role is skipped if:
// - The flag for creating the initial anonymous user role (`-create-initial-login-role`) is not provided.
// - The flag for skipping the creation of the initial anonymous user role (`-skip-initial-login-role-creation`) is provided.
//
// Returns:
// - bool: True if the creation should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipInitialLoginRoleCreation() (bool, string) {
	// If the version supports creating default and admin roles, we check the flag for creating the initial login role.
	if version.SupportsFeature(version.Binary, version.CreateDefaultAndAdminRoles) {
		// The flag for creating the initial login role takes precedence over the skip flag.
		if f.flagCreateInitialLoginRole {
			return false, reasonFlagWasSet(flagCreateInitialLoginRoleName)
		}
	}

	// TODO: Deprecated in 0.22
	if version.SupportsFeature(version.Binary, version.SkipDefaultAndAdminRoleCreation) {
		if f.flagSkipInitialLoginRoleCreation {
			return true, reasonFlagWasSet(flagSkipInitialLoginRoleName)
		}
	}
	return false, ""
}

// SkipInitialAuthenticatedUserRoleCreation checks if the creation of the initial authenticated user role should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// The creation of the initial authenticated user role is skipped if:
// - The flag for creating the initial authenticated user role (`-create-initial-authenticated-user-role`) is not provided.
// - The flag for skipping the creation of the initial authenticated user role (`-skip-initial-authenticated-user-role-creation`) is provided.
//
// Returns:
// - bool: True if the creation of the initial authenticated user role should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipInitialAuthenticatedUserRoleCreation() (bool, string) {
	if version.SupportsFeature(version.Binary, version.CreateDefaultAndAdminRoles) {
		// The flag for creating the initial login role takes precedence over the skip flag.
		if f.flagCreateInitialAuthenticatedUserRole {
			return false, reasonFlagWasSet(flagCreateInitialAuthenticatedUserRoleName)
		}
	}

	// TODO: Deprecated in 0.22
	if version.SupportsFeature(version.Binary, version.SkipDefaultAndAdminRoleCreation) {
		if f.flagSkipInitialAuthenticatedUserRoleCreation {
			return true, reasonFlagWasSet(flagSkipInitialAuthenticatedUserRoleName)
		}
	}
	return false, ""
}

// CreateInitialLoginRole checks if the initial anonymous login role should be created.
// It returns a boolean indicating whether to create and a reason string if creation is applicable.
//
// The initial login role is created if:
// - The flag for the creation of the initial anonymous user role (`-create-initial-login-role`) is provided.
//
// Returns:
// - bool: True if the role should be created, false otherwise.
// - string: A reason string explaining why the role is created, or an empty string if not created.
func (f *initFlags) CreateInitialLoginRole() (bool, string) {
	if f.flagCreateInitialLoginRole {
		return true, reasonFlagWasSet(flagCreateInitialLoginRoleName)
	}
	return false, ""
}

// CreateInitialAuthenticatedUserRole checks if the initial authenticated user role should be created.
// It returns a boolean indicating whether to create and a reason string if creation is applicable.
//
// The initial authenticated user role is created if:
// - The flag for the creation of the initial authenticated user role (`-create-initial-authenticated-user-role`) is provided.
//
// Returns:
// - bool: True if the initial authenticated user role should be created, false otherwise.
// - string: A reason string explaining why the role is created, or an empty string if not created.
func (f *initFlags) CreateInitialAuthenticatedUserRole() (bool, string) {
	if f.flagCreateInitialAuthenticatedUserRole {
		return true, reasonFlagWasSet(flagCreateInitialAuthenticatedUserRoleName)
	}
	return false, ""
}

// SkipAuthMethodCreation checks if the creation of authentication methods should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// Authentication method creation is skipped if:
// - The flag for skipping authentication method creation (`-skip-auth-method-creation`) is provided.
//
// Returns:
// - bool: True if the creation of authentication methods should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipAuthMethodCreation() (bool, string) {
	if f.flagSkipAuthMethodCreation {
		return true, reasonFlagWasSet(flagSkipAuthMethodName)
	}
	return false, ""
}

// SkipScopesCreation checks if the creation of default scopes should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// Scopes creation is skipped if:
// - The flag for skipping scopes creation (`-skip-scopes-creation`) is provided.
//
// Returns:
// - bool: True if the creation of scopes should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipScopesCreation() (bool, string) {
	if f.flagSkipScopesCreation {
		return true, reasonFlagWasSet(flagSkipScopesName)
	}
	return false, ""
}

// SkipHostResourcesCreation checks if the creation of default host resources should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// Host resources creation is skipped if:
// - The flag for skipping host resources creation (`-skip-host-resources-creation`) is provided.
// - Any of the dependent resources were skipped.
//
// Dependent resources include:
// - Scopes creation
//
// Returns:
// - bool: True if the creation of host resources should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipHostResourcesCreation() (bool, string) {
	if f.flagSkipHostResourcesCreation {
		return true, reasonFlagWasSet(flagSkipHostResourcesName)
	}
	return f.SkipScopesCreation()
}

// SkipTargetCreation checks if the creation of default targets should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// Target creation is skipped if:
// - The flag for skipping target creation (`-skip-target-creation`) is provided.
// - Any of the dependent resources were skipped.
//
// Dependent resources include:
// - Host resources creation
// - Scopes creation
//
// Returns:
// - bool: True if the creation of targets should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipTargetCreation() (bool, string) {
	if f.flagSkipTargetCreation {
		return true, reasonFlagWasSet(flagSkipTargetName)
	}
	if skip, reason := f.SkipHostResourcesCreation(); skip {
		return true, reason
	}
	return f.SkipScopesCreation()
}

// reasonFlagWasSet is a helper function that generates a reason string dynamically
// based on the provided flag name.
func reasonFlagWasSet(fn string) string {
	return fmt.Sprintf("flag `-%s` was set", fn)
}
