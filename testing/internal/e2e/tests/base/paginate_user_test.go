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
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateUsers asserts that the CLI automatically paginates to retrieve
// all users in a single invocation.
func TestCliPaginateUsers(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

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

	// Create enough users to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var userIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
		require.NoError(t, err)
		userIds = append(userIds, userId)
	}

	// List users
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialUsers users.UserListResult
	err = json.Unmarshal(output.Stdout, &initialUsers)
	require.NoError(t, err)

	var returnedIds []string
	for _, user := range initialUsers.Items {
		returnedIds = append(returnedIds, user.Id)
	}

	require.Len(t, initialUsers.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, userIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialUsers.ResponseType)
	assert.Empty(t, initialUsers.RemovedIds)
	assert.Empty(t, initialUsers.ListToken)

	// Create a new user and destroy one of the other users
	userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "delete",
			"-id", initialUsers.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new user but not the deleted user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newUsers users.UserListResult
	err = json.Unmarshal(output.Stdout, &newUsers)
	require.NoError(t, err)

	require.Len(t, newUsers.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new user
	firstItem := newUsers.Items[0]
	assert.Equal(t, userId, firstItem.Id)
	assert.Empty(t, newUsers.ResponseType)
	assert.Empty(t, newUsers.RemovedIds)
	assert.Empty(t, newUsers.ListToken)
	// Ensure the deleted user isn't returned
	for _, user := range newUsers.Items {
		assert.NotEqual(t, user.Id, initialUsers.Items[0].Id)
	}
}

// TestApiPaginateUsers asserts that the API automatically paginates to retrieve
// all users in a single invocation.
func TestApiPaginateUsers(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	uClient := users.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	// Create enough users to overflow a single page.
	var userIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
		require.NoError(t, err)
		userIds = append(userIds, userId)
	}

	// List users
	initialUsers, err := uClient.List(ctx, orgId)
	require.NoError(t, err)

	var returnedIds []string
	for _, user := range initialUsers.Items {
		returnedIds = append(returnedIds, user.Id)
	}

	require.Len(t, initialUsers.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, userIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialUsers.ResponseType)
	assert.Empty(t, initialUsers.RemovedIds)
	assert.NotEmpty(t, initialUsers.ListToken)
	mapItems, ok := initialUsers.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new user and destroy one of the other users
	userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
	require.NoError(t, err)
	_, err = uClient.Delete(ctx, initialUsers.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted user
	newUsers, err := uClient.List(ctx, orgId, users.WithListToken(initialUsers.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the users,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newUsers.Items), 1)
	// The first item should be the most recently created, which
	// should be our new user
	firstItem := newUsers.Items[0]
	assert.Equal(t, userId, firstItem.Id)
	assert.Equal(t, "complete", newUsers.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newUsers.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newUsers.RemovedIds, func(userId string) bool {
		return userId == initialUsers.Items[0].Id
	}))
	assert.NotEmpty(t, newUsers.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newUsers.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
