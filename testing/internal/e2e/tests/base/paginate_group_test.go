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
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateGroups asserts that the CLI automatically paginates to retrieve
// all groups in a single invocation.
func TestCliPaginateGroups(t *testing.T) {
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

	// Create enough groups to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var groupIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		groupId, err := boundary.CreateGroupApi(t, ctx, client, orgId)
		require.NoError(t, err)
		groupIds = append(groupIds, groupId)
	}

	// List groups
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialGroups groups.GroupListResult
	err = json.Unmarshal(output.Stdout, &initialGroups)
	require.NoError(t, err)

	var returnedIds []string
	for _, group := range initialGroups.Items {
		returnedIds = append(returnedIds, group.Id)
	}

	require.Len(t, initialGroups.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, groupIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialGroups.ResponseType)
	assert.Empty(t, initialGroups.RemovedIds)
	assert.Empty(t, initialGroups.ListToken)

	// Create a new group and destroy one of the other groups
	groupId, err := boundary.CreateGroupApi(t, ctx, client, orgId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "delete",
			"-id", initialGroups.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new group but not the deleted group
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newGroups groups.GroupListResult
	err = json.Unmarshal(output.Stdout, &newGroups)
	require.NoError(t, err)

	require.Len(t, newGroups.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new group
	firstItem := newGroups.Items[0]
	assert.Equal(t, groupId, firstItem.Id)
	assert.Empty(t, newGroups.ResponseType)
	assert.Empty(t, newGroups.RemovedIds)
	assert.Empty(t, newGroups.ListToken)
	// Ensure the deleted group isn't returned
	for _, group := range newGroups.Items {
		assert.NotEqual(t, group.Id, initialGroups.Items[0].Id)
	}
}

// TestApiPaginateGroups asserts that the API automatically paginates to retrieve
// all groups in a single invocation.
func TestApiPaginateGroups(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	uClient := groups.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	var groupIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		groupId, err := boundary.CreateGroupApi(t, ctx, client, orgId)
		require.NoError(t, err)
		groupIds = append(groupIds, groupId)
	}

	// List groups
	initialGroups, err := uClient.List(ctx, orgId)
	require.NoError(t, err)

	var returnedIds []string
	// Ignore the two precreated groups, which will appear at the end
	for _, group := range initialGroups.Items {
		returnedIds = append(returnedIds, group.Id)
	}

	require.Len(t, initialGroups.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, groupIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialGroups.ResponseType)
	assert.Empty(t, initialGroups.RemovedIds)
	assert.NotEmpty(t, initialGroups.ListToken)
	mapItems, ok := initialGroups.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new group and destroy one of the other groups
	groupId, err := boundary.CreateGroupApi(t, ctx, client, orgId)
	require.NoError(t, err)
	_, err = uClient.Delete(ctx, initialGroups.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted group
	newGroups, err := uClient.List(ctx, orgId, groups.WithListToken(initialGroups.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the groups,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newGroups.Items), 1)
	// The first item should be the most recently created, which
	// should be our new group
	firstItem := newGroups.Items[0]
	assert.Equal(t, groupId, firstItem.Id)
	assert.Equal(t, "complete", newGroups.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newGroups.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newGroups.RemovedIds, func(groupId string) bool {
		return groupId == initialGroups.Items[0].Id
	}))
	assert.NotEmpty(t, newGroups.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newGroups.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
