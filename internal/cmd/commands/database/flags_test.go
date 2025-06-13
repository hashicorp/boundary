// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"testing"

	"github.com/hashicorp/boundary/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitFlags_SkipInitialLoginRoleCreation(t *testing.T) {
	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
		wantErr        bool
		expectedErr    string
		version        string
	}{
		{
			name:           "SkipInitialLoginRoleCreation is true in 0.19.2",
			flags:          &initFlags{flagSkipInitialLoginRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-login-role-creation` was set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.2",
		},
		{
			name:           "SkipInitialLoginRoleCreation is true in 0.19.3",
			flags:          &initFlags{flagSkipInitialLoginRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-login-role-creation` was set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.3",
		},
		{
			name:           "SkipInitialLoginRoleCreation is false",
			flags:          &initFlags{flagSkipInitialLoginRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.3",
		},
		{
			name:           "CreateInitialLoginRole is true",
			flags:          &initFlags{flagCreateInitialLoginRole: true},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.22.0",
		},
		{
			name:           "CreateInitialLoginRole is false",
			flags:          &initFlags{flagCreateInitialLoginRole: false},
			expectedSkip:   true,
			expectedReason: "flag `-create-initial-login-role` was not set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.22.0",
		},
		{
			name:           "CreateInitialLoginRole is true and SkipInitialLoginRoleCreation is true",
			flags:          &initFlags{flagCreateInitialLoginRole: true, flagSkipInitialLoginRoleCreation: true},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        true,
			expectedErr:    "both `-create-initial-login-role` and `-skip-initial-login-role-creation` flags were set, only one can be set at a time",
			version:        "0.20.0",
		},
		{
			name:           "CreateInitialLoginRole is true and SkipInitialLoginRoleCreation is false",
			flags:          &initFlags{flagCreateInitialLoginRole: true, flagSkipInitialLoginRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.20.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// this is mutating state to update the version we're testing against
			// modify the globals that set which version the current binary is
			prevVer := version.Version
			defer func() {
				version.Version = prevVer
			}()
			version.Version = tt.version
			ver, _ := version.GetReleaseVersion()
			version.Binary = ver

			skip, reason, err := tt.flags.SkipInitialLoginRoleCreation()
			if tt.wantErr {
				assert.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipInitialAuthenticatedUserRoleCreation(t *testing.T) {
	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
		wantErr        bool
		expectedErr    string
		version        string
	}{
		{
			name:           "SkipInitialAuthenticatedUserRoleCreation is true in 0.19.2",
			flags:          &initFlags{flagSkipInitialAuthenticatedUserRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-authenticated-user-role-creation` was set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.2",
		},
		{
			name:           "SkipInitialAuthenticatedUserRoleCreation is true in 0.19.3",
			flags:          &initFlags{flagSkipInitialAuthenticatedUserRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-authenticated-user-role-creation` was set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.3",
		},
		{
			name:           "SkipInitialAuthenticatedUserRoleCreation is false",
			flags:          &initFlags{flagSkipInitialAuthenticatedUserRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.19.3",
		},
		{
			name:           "CreateInitialAuthenticatedUserRole is true",
			flags:          &initFlags{flagCreateInitialAuthenticatedUserRole: true},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.22.0",
		},
		{
			name:           "CreateInitialAuthenticatedUserRole is false",
			flags:          &initFlags{flagCreateInitialAuthenticatedUserRole: false},
			expectedSkip:   true,
			expectedReason: "flag `-create-initial-authenticated-user-role` was not set",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.22.0",
		},
		{
			name:           "CreateInitialAuthenticatedUserRole is true and SkipInitialAuthenticatedUserRoleCreation is true",
			flags:          &initFlags{flagCreateInitialAuthenticatedUserRole: true, flagSkipInitialAuthenticatedUserRoleCreation: true},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        true,
			expectedErr:    "both `-create-initial-authenticated-user-role` and `-skip-initial-authenticated-user-role-creation` flags were set, only one can be set at a time",
			version:        "0.20.0",
		},
		{
			name:           "CreateInitialAuthenticatedUserRole is true and SkipInitialAuthenticatedUserRoleCreation is false",
			flags:          &initFlags{flagCreateInitialAuthenticatedUserRole: true, flagSkipInitialAuthenticatedUserRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
			wantErr:        false,
			expectedErr:    "",
			version:        "0.20.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// this is mutating state to update the version we're testing against
			// modify the globals that set which version the current binary is
			prevVer := version.Version
			defer func() {
				version.Version = prevVer
			}()
			version.Version = tt.version
			ver, _ := version.GetReleaseVersion()
			version.Binary = ver

			skip, reason, err := tt.flags.SkipInitialAuthenticatedUserRoleCreation()
			if tt.wantErr {
				assert.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipAuthMethodCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipAuthMethodCreation is true",
			flags:          &initFlags{flagSkipAuthMethodCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-auth-method-creation` was set",
		},
		{
			name:           "SkipAuthMethodCreation is false",
			flags:          &initFlags{flagSkipAuthMethodCreation: false},
			expectedSkip:   false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipAuthMethodCreation()
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipScopesCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipScopesCreation is true",
			flags:          &initFlags{flagSkipScopesCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-scopes-creation` was set",
		},
		{
			name:           "SkipScopesCreation is false",
			flags:          &initFlags{flagSkipScopesCreation: false},
			expectedSkip:   false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipScopesCreation()
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipHostResourcesCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipHostResourcesCreation is true",
			flags:          &initFlags{flagSkipHostResourcesCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-host-resources-creation` was set",
		},
		{
			name:           "SkipScopesCreation is true",
			flags:          &initFlags{flagSkipScopesCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-scopes-creation` was set",
		},
		{
			name:           "No flags set",
			flags:          &initFlags{},
			expectedSkip:   false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipHostResourcesCreation()
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipTargetCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipTargetCreation is true",
			flags:          &initFlags{flagSkipTargetCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-target-creation` was set",
		},
		{
			name:           "SkipHostResourcesCreation is true",
			flags:          &initFlags{flagSkipHostResourcesCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-host-resources-creation` was set",
		},
		{
			name:           "SkipScopesCreation is true",
			flags:          &initFlags{flagSkipScopesCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-scopes-creation` was set",
		},
		{
			name:           "No flags set",
			flags:          &initFlags{},
			expectedSkip:   false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipTargetCreation()
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}
