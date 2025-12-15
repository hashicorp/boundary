// Copyright IBM Corp. 2020, 2025
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

// TestCliPaginateAuthMethods asserts that the CLI automatically paginates to retrieve
// all auth methods in a single invocation.
func TestCliPaginateAuthMethods(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create enough auth methods to overflow a single page.
	var authMethodIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		authMethodId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
		require.NoError(t, err)
		authMethodIds = append(authMethodIds, authMethodId)
	}

	// List auth methods
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "list",
			"-scope-id", orgId,
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
	authMethodId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
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
			"-scope-id", orgId,
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
	assert.Equal(t, authMethodId, firstItem.Id)
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
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	amClient := authmethods.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err = sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	// Create enough auth methods to overflow a single page.
	var authMethodIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		authMethodId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
		require.NoError(t, err)
		authMethodIds = append(authMethodIds, authMethodId)
	}

	// List auth methods
	initialAuthMethods, err := amClient.List(ctx, orgId)
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
	authMethodId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	_, err = amClient.Delete(ctx, initialAuthMethods.Items[0].Id)
	require.NoError(t, err)

	// List auth methods again, should have new one but not old one
	newAuthMethods, err := amClient.List(ctx, orgId, authmethods.WithListToken(initialAuthMethods.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the auth methods,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newAuthMethods.Items), 1)
	// The first item should be the most recently created, which
	// should be our new auth method
	firstItem := newAuthMethods.Items[0]
	assert.Equal(t, authMethodId, firstItem.Id)
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
