// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliAuthMethodPassword uses the boundary cli to create a new password auth
// method, set it as the primary auth method for a scope, and log in to boundary
// using a new account in that auth method.
func TestCliAuthMethodPassword(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create new auth method
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "create", "password",
			"-scope-id", newOrgId,
			"-name", "e2e Auth Method",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newAuthMethodResult authmethods.AuthMethodCreateResult
	err := json.Unmarshal(output.Stdout, &newAuthMethodResult)
	require.NoError(t, err)
	newAuthMethodId := newAuthMethodResult.Item.Id
	// Need to manually clean up auth method until ICU-7833 is addressed
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("auth-methods", "delete", "-id", newAuthMethodId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Auth Method Id: %s", newAuthMethodId)

	// Create account in auth method
	testAccountName := "test-account"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, newAuthMethodId, testAccountName)

	// Create user and attach new account
	newUserId := boundary.CreateNewUserCli(t, ctx, newOrgId)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", newUserId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Set new account as primary auth method for the new org
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "update",
			"-id", newOrgId,
			"-primary-auth-method-id", newAuthMethodId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var updateScopeResult scopes.ScopeUpdateResult
	err = json.Unmarshal(output.Stdout, &updateScopeResult)
	require.NoError(t, err)
	require.Equal(t, newAuthMethodId, updateScopeResult.Item.PrimaryAuthMethodId)

	// Log in as the new user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "password",
			"-scope-id", newOrgId,
			"-login-name", testAccountName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", acctPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
