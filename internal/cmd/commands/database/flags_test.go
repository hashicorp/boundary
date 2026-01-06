// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitFlags_SkipInitialLoginRoleCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipInitialLoginRoleCreation is true",
			flags:          &initFlags{flagSkipInitialLoginRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-login-role-creation` was set",
		},
		{
			name:           "SkipInitialLoginRoleCreation is false",
			flags:          &initFlags{flagSkipInitialLoginRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipInitialLoginRoleCreation()
			assert.Equal(t, tt.expectedSkip, skip)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestInitFlags_SkipInitialAuthenticatedUserRoleCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		flags          *initFlags
		expectedSkip   bool
		expectedReason string
	}{
		{
			name:           "SkipInitialAuthenticatedUserRoleCreation is true",
			flags:          &initFlags{flagSkipInitialAuthenticatedUserRoleCreation: true},
			expectedSkip:   true,
			expectedReason: "flag `-skip-initial-authenticated-user-role-creation` was set",
		},
		{
			name:           "SkipInitialAuthenticatedUserRoleCreation is false",
			flags:          &initFlags{flagSkipInitialAuthenticatedUserRoleCreation: false},
			expectedSkip:   false,
			expectedReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			skip, reason := tt.flags.SkipInitialAuthenticatedUserRoleCreation()
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
