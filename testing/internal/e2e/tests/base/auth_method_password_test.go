// Copyright (c) HashiCorp, Inc.
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

	// Set new auth method as primary auth method for the new org
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

	// Log in with the new account
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

	// Verify that a new user was automatically created with the new account attached
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-scope-id", newOrgId,
			"-format", "json",
		),
	)
	require.NoError(t, err, string(output.Stderr))
	var usersListResult users.UserListResult
	err = json.Unmarshal(output.Stdout, &usersListResult)
	require.NoError(t, err)
	require.Equal(t, newAccountId, usersListResult.Items[0].PrimaryAccountId)

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
	require.Equal(t, newAccountId, usersReadResult.Item.PrimaryAccountId)
	require.Contains(t, usersReadResult.Item.AccountIds, newAccountId)

	// Create a new account and manually attach it to a new user
	newUserId := boundary.CreateNewUserCli(t, ctx, newOrgId)
	testAccountName = "test-account2"
	newAccountId, acctPassword = boundary.CreateNewAccountCli(t, ctx, newAuthMethodId, testAccountName)
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Log in with the new account
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
