// Copyright (c) HashiCorp, Inc.
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
func TestScopePermissions(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)

	//Create new account
	const testAccountName = "test-account"
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, testAccountName)
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	//create new user
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)
	//Find Ids of the roles to be modified
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("roles", "list", "--recursive", "-format", "json"))
	var rolesListResult roles.RoleListResult
	err = json.Unmarshal(output.Stdout, &rolesListResult)
	require.NoError(t, err)
	var loginGrantsRoleId string
	var authenticatedUserGrantsRoleId string
	var loginAndDefaultGrantsRoleId string
	for _, item := range rolesListResult.Items {
		if item.Name == "Login and Default Grants" {
			loginAndDefaultGrantsRoleId = item.Id
		}
		if item.Name == "Login Grants" {
			loginGrantsRoleId = item.Id
		}
		if item.Name == "Authenticated User Grants" {
			authenticatedUserGrantsRoleId = item.Id
		}
	}
	//Modify login and default grants role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"))
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
	require.NoError(t, output.Err, string(output.Stderr))

	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "remove-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
		require.NoError(t, output.Err, string(output.Stderr))
		output = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "add-grants", "-id", loginAndDefaultGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	//Modify login grants role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"))
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
	require.NoError(t, output.Err, string(output.Stderr))

	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "remove-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list"))
		require.NoError(t, output.Err, string(output.Stderr))
		output = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "add-grants", "-id", loginGrantsRoleId, "-grant", "ids=*;type=scope;actions=list,no-op"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	//modify authenticated user role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "remove-grants", "-id", authenticatedUserGrantsRoleId, "-grant", "ids=*;type=scope;actions=read"))
	require.NoError(t, output.Err, string(output.Stderr))

	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "add-grants", "-id", authenticatedUserGrantsRoleId, "-grant", "ids=*;type=scope;actions=read"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	//Create new project
	projectId, err := boundary.CreateProjectCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("scopes", "delete", "-id", projectId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	//Create role in global scope
	roleId, err := boundary.CreateRoleCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("roles", "delete", "-id", roleId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-grants", "-id", roleId, "-grant", fmt.Sprintf(`ids=%s;type=scope;actions=list,read`, projectId)),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	//Add user as a principal for the role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("roles", "add-principals", "-id", roleId, "-principal", userId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	//login as created user
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, testAccountName, acctPassword)
	require.NoError(t, err)
	//List scopes as the user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("scopes", "list", "--recursive", "-format", "json"))
	require.NoError(t, output.Err, string(output.Stderr))
	//Only the new project should be listed
	var scopesListResult scopes.ScopeListResult
	err = json.Unmarshal(output.Stdout, &scopesListResult)
	require.NoError(t, err)
	var listedIds []string
	for _, item := range scopesListResult.Items {
		listedIds = append(listedIds, item.Id)
	}
	require.Equal(t, 1, len(listedIds))
	require.Equal(t, projectId, listedIds[0])
}
