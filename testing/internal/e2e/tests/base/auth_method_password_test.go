// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
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

// TestCliPaginateAuthMethods asserts that the CLI automatically paginates to retrieve
// all auth methods in a single invocation.
func TestCliPaginateAuthMethods(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create enough auth methods to overflow a single page.
	var authMethodIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		authMethodId := boundary.CreateNewAuthMethodApi(t, ctx, client, newOrgId)
		authMethodIds = append(authMethodIds, authMethodId)
	}

	// List auth methods
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "list",
			"-scope-id", newOrgId,
			"-recursive",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var initialAuthMethods authmethods.AuthMethodListResult
	err = json.Unmarshal(output.Stdout, &initialAuthMethods)
	require.NoError(t, err)

	var returnedIds []string
	for _, authMethod := range initialAuthMethods.Items {
		returnedIds = append(returnedIds, authMethod.Id)
	}
	require.Len(t, initialAuthMethods.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, authMethodIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialAuthMethods.ResponseType)
	assert.Empty(t, initialAuthMethods.RemovedIds)
	assert.Empty(t, initialAuthMethods.ListToken)

	// Create a new auth method and destroy one of the other auth methods
	newAuthMethodId := boundary.CreateNewAuthMethodApi(t, ctx, client, newOrgId)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "delete",
			"-id", initialAuthMethods.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List auth methods again, should have new one but not old one
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "list",
			"-scope-id", newOrgId,
			"-recursive",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAuthMethods authmethods.AuthMethodListResult
	err = json.Unmarshal(output.Stdout, &newAuthMethods)
	require.NoError(t, err)

	require.Len(t, newAuthMethods.Items, c.MaxPageSize+1)
	// The first item should be the most recently created,
	// which should be the new auth method
	firstItem := newAuthMethods.Items[0]
	assert.Equal(t, newAuthMethodId, firstItem.Id)
	assert.Empty(t, initialAuthMethods.ResponseType)
	assert.Empty(t, initialAuthMethods.RemovedIds)
	assert.Empty(t, initialAuthMethods.ListToken)
	// Ensure the deleted auth method isn't returned
	for _, authMethod := range newAuthMethods.Items {
		assert.NotEqual(t, initialAuthMethods.Items[0].Id, authMethod.Id)
	}
}

// TestApiPaginateAuthMethods asserts that the API automatically paginates to retrieve
// all auth methods in a single invocation.
func TestApiPaginateAuthMethods(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	adminToken := client.Token()
	ctx := context.Background()
	sClient := scopes.NewClient(client)
	amClient := authmethods.NewClient(client)
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err = sClient.Delete(ctx, newOrgId)
		require.NoError(t, err)
	})

	// Create enough auth methods to overflow a single page.
	var authMethodIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		authMethodIds = append(authMethodIds, boundary.CreateNewAuthMethodApi(t, ctx, client, newOrgId))
	}

	// List auth methods
	initialAuthMethods, err := amClient.List(ctx, newOrgId, authmethods.WithRecursive(true))
	require.NoError(t, err)

	var returnedIds []string
	for _, authMethod := range initialAuthMethods.Items {
		returnedIds = append(returnedIds, authMethod.Id)
	}

	require.Len(t, initialAuthMethods.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, authMethodIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialAuthMethods.ResponseType)
	assert.Empty(t, initialAuthMethods.RemovedIds)
	assert.NotEmpty(t, initialAuthMethods.ListToken)
	mapItems, ok := initialAuthMethods.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new auth method and destroy one of the other auth methods
	newAuthMethodId := boundary.CreateNewAuthMethodApi(t, ctx, client, newOrgId)
	_, err = amClient.Delete(ctx, initialAuthMethods.Items[0].Id)
	require.NoError(t, err)

	// List auth methods again, should have new one but not old one
	newAuthMethods, err := amClient.List(ctx, newOrgId, authmethods.WithListToken(initialAuthMethods.ListToken), authmethods.WithRecursive(true))
	require.NoError(t, err)

	// Note that this will likely contain all the auth methods,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newAuthMethods.Items), 1)
	// The first item should be the most recently created, which
	// should be our new auth method
	firstItem := newAuthMethods.Items[0]
	assert.Equal(t, newAuthMethodId, firstItem.Id)
	assert.Equal(t, "complete", newAuthMethods.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newAuthMethods.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newAuthMethods.RemovedIds, func(authMethodId string) bool {
		return authMethodId == initialAuthMethods.Items[0].Id
	}))
	assert.NotEmpty(t, newAuthMethods.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newAuthMethods.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
