// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateAccounts asserts that the CLI automatically paginates to retrieve
// all accounts in a single invocation.
func TestCliPaginateAccounts(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
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
	amId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("auth-methods", "delete", "-id", amId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create enough accounts to overflow a single page.
	var accountIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		accId, _, err := boundary.CreateAccountApi(t, ctx, client, amId, "testuser-"+strconv.Itoa(i))
		require.NoError(t, err)
		accountIds = append(accountIds, accId)
	}

	// List accounts
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts", "list",
			"-auth-method-id", amId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialAccounts accounts.AccountListResult
	err = json.Unmarshal(output.Stdout, &initialAccounts)
	require.NoError(t, err)

	var returnedIds []string
	for _, account := range initialAccounts.Items {
		returnedIds = append(returnedIds, account.Id)
	}

	require.Len(t, initialAccounts.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, accountIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialAccounts.ResponseType)
	assert.Empty(t, initialAccounts.RemovedIds)
	assert.Empty(t, initialAccounts.ListToken)

	// Create a new account and destroy one of the other accounts
	accountId, _, err := boundary.CreateAccountApi(t, ctx, client, amId, "newuser")
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts", "delete",
			"-id", initialAccounts.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new account but not the deleted account
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts", "list",
			"-auth-method-id", amId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAccounts accounts.AccountListResult
	err = json.Unmarshal(output.Stdout, &newAccounts)
	require.NoError(t, err)

	require.Len(t, newAccounts.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new account
	firstItem := newAccounts.Items[0]
	assert.Equal(t, accountId, firstItem.Id)
	assert.Empty(t, newAccounts.ResponseType)
	assert.Empty(t, newAccounts.RemovedIds)
	assert.Empty(t, newAccounts.ListToken)
	// Ensure the deleted account isn't returned
	for _, account := range newAccounts.Items {
		assert.NotEqual(t, account.Id, initialAccounts.Items[0].Id)
	}
}

// TestApiPaginateAccounts asserts that the API automatically paginates to retrieve
// all accounts in a single invocation.
func TestApiPaginateAccounts(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	adminToken := client.Token()
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	amClient := authmethods.NewClient(client)
	acClient := accounts.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err = sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	amId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err := amClient.Delete(ctx, amId)
		require.NoError(t, err)
	})

	// Create enough accounts to overflow a single page.
	var accountIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		accId, _, err := boundary.CreateAccountApi(t, ctx, client, amId, "testuser-"+strconv.Itoa(i))
		require.NoError(t, err)
		accountIds = append(accountIds, accId)
	}

	// List accounts
	initialAccounts, err := acClient.List(ctx, amId)
	require.NoError(t, err)

	var returnedIds []string
	for _, account := range initialAccounts.Items {
		returnedIds = append(returnedIds, account.Id)
	}

	require.Len(t, initialAccounts.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, accountIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialAccounts.ResponseType)
	assert.Empty(t, initialAccounts.RemovedIds)
	assert.NotEmpty(t, initialAccounts.ListToken)
	mapItems, ok := initialAccounts.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new account and destroy one of the other accounts
	accountId, _, err := boundary.CreateAccountApi(t, ctx, client, amId, "newuser")
	require.NoError(t, err)
	_, err = acClient.Delete(ctx, initialAccounts.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted account
	newAccounts, err := acClient.List(ctx, amId, accounts.WithListToken(initialAccounts.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the accounts,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newAccounts.Items), 1)
	// The first item should be the most recently created, which
	// should be our new account
	firstItem := newAccounts.Items[0]
	assert.Equal(t, accountId, firstItem.Id)
	assert.Equal(t, "complete", newAccounts.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newAccounts.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newAccounts.RemovedIds, func(accountId string) bool {
		return accountId == initialAccounts.Items[0].Id
	}))
	assert.NotEmpty(t, newAccounts.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newAccounts.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
