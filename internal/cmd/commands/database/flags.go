// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import "fmt"

const (
	flagConfigName                           = "config"
	flagConfigKmsName                        = "config-kms"
	flagLogLevelName                         = "log-level"
	flagLogFormatName                        = "log-format"
	flagSkipInitialLoginRoleName             = "skip-initial-login-role-creation"
	flagSkipInitialAuthenticatedUserRoleName = "skip-initial-authenticated-user-role-creation"
	flagSkipAuthMethodName                   = "skip-auth-method-creation"
	flagSkipScopesName                       = "skip-scopes-creation"
	flagSkipHostResourcesName                = "skip-host-resources-creation"
	flagSkipTargetName                       = "skip-target-creation"
	flagMigrationUrlName                     = "migration-url"
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
	flagSkipAuthMethodCreation                   bool
	flagSkipScopesCreation                       bool
	flagSkipHostResourcesCreation                bool
	flagSkipTargetCreation                       bool
}

// SkipInitialLoginRoleCreation checks if the creation of the initial anonymous login role should be skipped.
// It returns a boolean indicating whether to skip and a reason string if skipping is applicable.
//
// The creation of the initial login role is skipped if:
// - The flag for skipping the creation of the initial anonymous user role (`-skip-initial-login-role-creation`) is provided.
//
// Returns:
// - bool: True if the creation should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipInitialLoginRoleCreation() (bool, string) {
	if f.flagSkipInitialLoginRoleCreation {
		return true, reasonFlagWasSet(flagSkipInitialLoginRoleName)
	}
	return false, ""
}

// SkipInitialAuthenticatedUserRoleCreation checks if the creation of the initial authenticated user role should be skipped.
// It returns a boolean indicating whether to skip and a reason string explaining why the creation is skipped.
//
// The creation of the initial authenticated user role is skipped if:
// - The flag for skipping the creation of the initial authenticated user role (`-skip-initial-authenticated-user-role-creation`) is provided.
//
// Returns:
// - bool: True if the creation of the initial authenticated user role should be skipped, false otherwise.
// - string: A reason string explaining why the creation is skipped, or an empty string if not skipped.
func (f *initFlags) SkipInitialAuthenticatedUserRoleCreation() (bool, string) {
	if f.flagSkipInitialAuthenticatedUserRoleCreation {
		return true, reasonFlagWasSet(flagSkipInitialAuthenticatedUserRoleName)
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
