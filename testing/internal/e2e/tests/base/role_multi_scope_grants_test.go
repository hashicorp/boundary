// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliApplyGrantsForMultipleScopes verifies if roles' grants can be applied for children and descendant scopes
func TestCliApplyGrantsForMultipleScopes(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)

	// Create Org and Project
	orgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId := boundary.CreateNewProjectCli(t, ctx, orgId)

	// Create Account
	acctName := "e2e-account"
	accountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, bc.AuthMethodId, acctName)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create User and set Account to it
	userId := boundary.CreateNewUserCli(t, ctx, "global")
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.SetAccountToUserCli(t, ctx, userId, accountId)

	// Authenticate test user and try to:
	// - list Roles in global scope: expect error
	// - list Roles in org scope: expect error
	// - list Roles in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)

	_, err = boundary.CreateRoleCli(t, ctx, "global")
	require.Error(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, orgId)
	require.Error(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, projectId)
	require.Error(t, err)

	// Create Role, and add grants and principal to it
	boundary.AuthenticateAdminCli(t, ctx)
	roleId, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", roleId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=role;actions=list")
	boundary.AddPrincipalToRoleCli(t, ctx, roleId, userId)

	// Authenticate User and try to:
	// - list Roles in global scope: expect success
	// - list Roles in org scope: expect error
	// - list Roles in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	_, err = boundary.ListRolesCli(t, ctx, "global")
	require.NoError(t, err)

	_, err = boundary.ListRolesCli(t, ctx, orgId)
	require.Error(t, err)

	_, err = boundary.ListRolesCli(t, ctx, projectId)
	require.Error(t, err)

	// Set Grant Scopes to Role: this, children
	boundary.AuthenticateAdminCli(t, ctx)
	err = boundary.SetGrantScopesToRoleCli(t, ctx, roleId,
		boundary.WithGrantScopeId("this"),
		boundary.WithGrantScopeId("children"),
	)
	require.NoError(t, err)

	// Authenticate User and try to:
	// - list Roles in global scope: expect success
	// - list Roles in org scope: expect success
	// - list Roles in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	_, err = boundary.ListRolesCli(t, ctx, "global")
	require.NoError(t, err)

	_, err = boundary.ListRolesCli(t, ctx, orgId)
	require.NoError(t, err)

	_, err = boundary.ListRolesCli(t, ctx, projectId)
	require.Error(t, err)

	// Set Grant Scopes to Role: this, descendants
	boundary.AuthenticateAdminCli(t, ctx)
	err = boundary.SetGrantScopesToRoleCli(t, ctx, roleId,
		boundary.WithGrantScopeId("this"),
		boundary.WithGrantScopeId("descendants"),
	)
	require.NoError(t, err)

	// Authenticate User and try to:
	// - list Roles in global scope: expect success
	// - list Roles in org scope: expect success
	// - list Roles in proj scope: expect success
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	_, err = boundary.ListRolesCli(t, ctx, "global")
	require.NoError(t, err)

	_, err = boundary.ListRolesCli(t, ctx, orgId)
	require.NoError(t, err)

	_, err = boundary.ListRolesCli(t, ctx, projectId)
	require.NoError(t, err)
}
