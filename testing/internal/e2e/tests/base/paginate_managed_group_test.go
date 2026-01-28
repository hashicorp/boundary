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
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateManagedGroups asserts that the CLI automatically paginates to retrieve
// all managed groups in a single invocation.
func TestCliPaginateManagedGroups(t *testing.T) {
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
	amId, err := boundary.CreateOidcAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("auth-methods", "delete", "-id", amId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create enough managedgroups to overflow a single page.
	var managedgroupIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		managedGroupId, err := boundary.CreateManagedGroupApi(t, ctx, client, amId)
		require.NoError(t, err)
		managedgroupIds = append(managedgroupIds, managedGroupId)
	}

	// List managedgroups
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "list",
			"-auth-method-id", amId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialManagedGroups managedgroups.ManagedGroupListResult
	err = json.Unmarshal(output.Stdout, &initialManagedGroups)
	require.NoError(t, err)

	var returnedIds []string
	for _, managedgroup := range initialManagedGroups.Items {
		returnedIds = append(returnedIds, managedgroup.Id)
	}

	require.Len(t, initialManagedGroups.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, managedgroupIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialManagedGroups.ResponseType)
	assert.Empty(t, initialManagedGroups.RemovedIds)
	assert.Empty(t, initialManagedGroups.ListToken)

	// Create a new managedgroup and destroy one of the other managed groups
	managedGroupId, err := boundary.CreateManagedGroupApi(t, ctx, client, amId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "delete",
			"-id", initialManagedGroups.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new managedgroup but not the deleted managed group
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "list",
			"-auth-method-id", amId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newManagedGroups managedgroups.ManagedGroupListResult
	err = json.Unmarshal(output.Stdout, &newManagedGroups)
	require.NoError(t, err)

	require.Len(t, newManagedGroups.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new managedgroup
	firstItem := newManagedGroups.Items[0]
	assert.Equal(t, managedGroupId, firstItem.Id)
	assert.Empty(t, newManagedGroups.ResponseType)
	assert.Empty(t, newManagedGroups.RemovedIds)
	assert.Empty(t, newManagedGroups.ListToken)
	// Ensure the deleted managedgroup isn't returned
	for _, managedgroup := range newManagedGroups.Items {
		assert.NotEqual(t, managedgroup.Id, initialManagedGroups.Items[0].Id)
	}
}

// TestApiPaginateManagedGroups asserts that the API automatically paginates to retrieve
// all managedgroups in a single invocation.
func TestApiPaginateManagedGroups(t *testing.T) {
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
	mgClient := managedgroups.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err = sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	amId, err := boundary.CreateOidcAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err := amClient.Delete(ctx, amId)
		require.NoError(t, err)
	})

	// Create enough managedgroups to overflow a single page.
	var managedgroupIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		managedGroupId, err := boundary.CreateManagedGroupApi(t, ctx, client, amId)
		require.NoError(t, err)
		managedgroupIds = append(managedgroupIds, managedGroupId)
	}

	// List managedgroups
	initialManagedGroups, err := mgClient.List(ctx, amId)
	require.NoError(t, err)

	var returnedIds []string
	for _, managedgroup := range initialManagedGroups.Items {
		returnedIds = append(returnedIds, managedgroup.Id)
	}

	require.Len(t, initialManagedGroups.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, managedgroupIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialManagedGroups.ResponseType)
	assert.Empty(t, initialManagedGroups.RemovedIds)
	assert.NotEmpty(t, initialManagedGroups.ListToken)
	mapItems, ok := initialManagedGroups.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new managedgroup and destroy one of the other managed groups
	managedGroupId, err := boundary.CreateManagedGroupApi(t, ctx, client, amId)
	require.NoError(t, err)
	_, err = mgClient.Delete(ctx, initialManagedGroups.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted managedgroup
	newManagedGroups, err := mgClient.List(ctx, amId, managedgroups.WithListToken(initialManagedGroups.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the managed groups,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newManagedGroups.Items), 1)
	// The first item should be the most recently created, which
	// should be our new managedgroup
	firstItem := newManagedGroups.Items[0]
	assert.Equal(t, managedGroupId, firstItem.Id)
	assert.Equal(t, "complete", newManagedGroups.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newManagedGroups.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newManagedGroups.RemovedIds, func(managedgroupId string) bool {
		return managedgroupId == initialManagedGroups.Items[0].Id
	}))
	assert.NotEmpty(t, newManagedGroups.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newManagedGroups.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
