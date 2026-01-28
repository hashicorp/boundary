// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestScopePermissions tests an issue with listing scopes
// When a user is only given permission to only list single project in a scope,
// the user should only see that project and no error should be displayed
func TestScopePermissions(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)

	// Create Org and 2 Projects
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	projectId2, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)

	// Create new account
	const testAccountName = "test-account"
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, testAccountName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create new user
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)

	// Find Ids of the roles to be modified
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("roles", "list", "-format", "json"))
	var rolesListResult roles.RoleListResult
	err = json.Unmarshal(output.Stdout, &rolesListResult)
	require.NoError(t, err)
	var loginGrantsRoleId string
	var authenticatedUserGrantsRoleId string
	var loginAndDefaultGrantsRoleId string
	for _, item := range rolesListResult.Items {
		if item.Name == "Login Grants" {
			loginGrantsRoleId = item.Id
		}
		if item.Name == "Authenticated User Grants" {
			authenticatedUserGrantsRoleId = item.Id
		}
	}
	output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("roles", "list", "-format", "json", "-scope-id", orgId))
	err = json.Unmarshal(output.Stdout, &rolesListResult)
	require.NoError(t, err)
	for _, item := range rolesListResult.Items {
		if item.Name == "Login and Default Grants" {
			loginAndDefaultGrantsRoleId = item.Id
		}
	}

	// In the org, prevent the user from being able to list all scopes
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"))
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
	require.NoError(t, output.Err, string(output.Stderr))

	// In global, remove the no-op permission from the login role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"))
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
	require.NoError(t, output.Err, string(output.Stderr))

	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "remove-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
		require.NoError(t, output.Err, string(output.Stderr))
		output = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "add-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// In global, prevent the user from being able to read all scopes
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", authenticatedUserGrantsRoleId, "-grant", "ids=*;type=scope;actions=read"))
	require.NoError(t, output.Err, string(output.Stderr))

	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "add-grants", "-id", authenticatedUserGrantsRoleId, "-grant", "ids=*;type=scope;actions=read"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create role in org and add ability to list and read a project in the org
	roleId, err := boundary.CreateRoleCli(t, ctx, orgId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", roleId, "-grant", fmt.Sprintf(`ids=%s;type=scope;actions=list,read`, projectId)),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	// Add user as a principal for the role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-principals", "-id", roleId, "-principal", userId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	// Log in as created user
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, testAccountName, acctPassword)
	require.NoError(t, err)

	// List scopes as the user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("scopes", "list", "-scope-id", orgId, "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))

	// Only the new project should be listed
	var scopesListResult scopes.ScopeListResult
	err = json.Unmarshal(output.Stdout, &scopesListResult)
	require.NoError(t, err)
	var listedIds []string
	for _, item := range scopesListResult.Items {
		listedIds = append(listedIds, item.Id)
	}
	require.Equal(t, 1, len(listedIds))
	require.Equal(t, projectId, listedIds[0])

	// Check user can only read the assigned project
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("scopes", "read", "-id", projectId))
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("scopes", "read", "-id", projectId2))
	require.Error(t, output.Err, "Error from controller when performing read on scope")
}
