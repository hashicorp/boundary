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
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)

	// Create Account
	acctName := "e2e-account"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, bc.AuthMethodId, acctName)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", newAccountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create User and set Account to it
	newUserId := boundary.CreateNewUserCli(t, ctx, "global")
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", newUserId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Create Role and add admin grants to it
	newRoleId, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", newRoleId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.AddGrantToRoleCli(t, ctx, newRoleId, "ids=*;type=*;actions=*")

	// Authenticate test user and try to:
	// - create role in global scope: expect error
	// - create role in org scope: expect error
	// - create role in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)

	_, err = boundary.CreateRoleCli(t, ctx, "global")
	require.Error(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, newOrgId)
	require.Error(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, newProjectId)
	require.Error(t, err)

	// Add User as a principle to the admin Role
	boundary.AuthenticateAdminCli(t, ctx)
	boundary.AddPrincipalToRoleCli(t, ctx, newRoleId, newUserId)

	// Authenticate User and try to:
	// - create Role in global scope: expect success
	// - create Role in org scope: expect error
	// - create Role in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	newGlobalRoleId2, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", newGlobalRoleId2),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	_, err = boundary.CreateRoleCli(t, ctx, newOrgId)
	require.Error(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, newProjectId)
	require.Error(t, err)

	// Set Grant Scopes to Role: this, children
	boundary.AuthenticateAdminCli(t, ctx)
	err = boundary.SetGrantScopesToRoleCli(t, ctx, newRoleId,
		boundary.WithGrantScopeId("this"),
		boundary.WithGrantScopeId("children"),
	)
	require.NoError(t, err)

	// Authenticate User and try to:
	// - create Role in global scope: expect success
	// - create Role in org scope: expect success
	// - create Role in proj scope: expect error
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	newGlobalRoleId3, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", newGlobalRoleId3),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	_, err = boundary.CreateRoleCli(t, ctx, newOrgId)
	require.NoError(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, newProjectId)
	require.Error(t, err)

	// Set Grant Scopes to Role: this, descendants
	boundary.AuthenticateAdminCli(t, ctx)
	err = boundary.SetGrantScopesToRoleCli(t, ctx, newRoleId,
		boundary.WithGrantScopeId("this"),
		boundary.WithGrantScopeId("descendants"),
	)
	require.NoError(t, err)

	// Authenticate User and try to:
	// - create Role in global scope: expect success
	// - create Role in org scope: expect success
	// - create Role in proj scope: expect success
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	newGlobalRoleId4, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", newGlobalRoleId4),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	_, err = boundary.CreateRoleCli(t, ctx, newOrgId)
	require.NoError(t, err)

	_, err = boundary.CreateRoleCli(t, ctx, newProjectId)
	require.NoError(t, err)
}
