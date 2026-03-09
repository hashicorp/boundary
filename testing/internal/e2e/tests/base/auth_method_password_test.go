// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliAuthMethodPassword uses the boundary cli to create a new password auth
// method, set it as the primary auth method for a scope, and log in to boundary
// using a new account in that auth method.
func TestCliAuthMethodPassword(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create new auth method
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "create", "password",
			"-scope-id", orgId,
			"-name", "e2e Auth Method",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newAuthMethodResult authmethods.AuthMethodCreateResult
	err = json.Unmarshal(output.Stdout, &newAuthMethodResult)
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
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, newAuthMethodId, testAccountName)
	require.NoError(t, err)

	// Set new auth method as primary auth method for the new org
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "update",
			"-id", orgId,
			"-primary-auth-method-id", newAuthMethodId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var updateScopeResult scopes.ScopeUpdateResult
	err = json.Unmarshal(output.Stdout, &updateScopeResult)
	require.NoError(t, err)
	require.Equal(t, newAuthMethodId, updateScopeResult.Item.PrimaryAuthMethodId)

	// Log in with the new account
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "password",
			"-scope-id", orgId,
			"-login-name", testAccountName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", acctPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Verify that a new user was automatically created with the new account attached
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-scope-id", orgId,
			"-format", "json",
		),
	)
	require.NoError(t, err, string(output.Stderr))
	var usersListResult users.UserListResult
	err = json.Unmarshal(output.Stdout, &usersListResult)
	require.NoError(t, err)
	require.Equal(t, accountId, usersListResult.Items[0].PrimaryAccountId)

	userId := usersListResult.Items[0].Id
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "read",
			"-id", userId,
			"-format", "json",
		),
	)
	require.NoError(t, err, string(output.Stderr))
	var usersReadResult users.UserReadResult
	err = json.Unmarshal(output.Stdout, &usersReadResult)
	require.NoError(t, err)
	require.Equal(t, accountId, usersReadResult.Item.PrimaryAccountId)
	require.Contains(t, usersReadResult.Item.AccountIds, accountId)

	// Create a new account and manually attach it to a new user
	newUserId, err := boundary.CreateUserCli(t, ctx, orgId)
	require.NoError(t, err)
	testAccountName = "test-account2"
	accountId, acctPassword, err = boundary.CreateAccountCli(t, ctx, newAuthMethodId, testAccountName)
	require.NoError(t, err)
	err = boundary.SetAccountToUserCli(t, ctx, newUserId, accountId)
	require.NoError(t, err)

	// Log in with the new account
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "password",
			"-scope-id", orgId,
			"-login-name", testAccountName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", acctPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
