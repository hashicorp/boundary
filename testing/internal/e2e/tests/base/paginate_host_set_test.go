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
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateHostSets asserts that the CLI automatically paginates to retrieve
// all host sets in a single invocation.
func TestCliPaginateHostSets(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)

	// Create enough host sets to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var hostSetIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostSetIds = append(hostSetIds, boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId))
	}

	// List host sets
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "list",
			"-host-catalog-id", newHostCatalogId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialHostSets hostsets.HostSetListResult
	err = json.Unmarshal(output.Stdout, &initialHostSets)
	require.NoError(t, err)

	var returnedIds []string
	for _, hostSet := range initialHostSets.Items {
		returnedIds = append(returnedIds, hostSet.Id)
	}

	require.Len(t, initialHostSets.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostSetIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialHostSets.ResponseType)
	assert.Empty(t, initialHostSets.RemovedIds)
	assert.Empty(t, initialHostSets.ListToken)

	// Create a new host set and destroy one of the other host sets
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "delete",
			"-id", initialHostSets.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new host set but not the deleted host set
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "list",
			"-host-catalog-id", newHostCatalogId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newHostSets hostsets.HostSetListResult
	err = json.Unmarshal(output.Stdout, &newHostSets)
	require.NoError(t, err)

	require.Len(t, newHostSets.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new host set
	firstItem := newHostSets.Items[0]
	assert.Equal(t, newHostSetId, firstItem.Id)
	assert.Empty(t, newHostSets.ResponseType)
	assert.Empty(t, newHostSets.RemovedIds)
	assert.Empty(t, newHostSets.ListToken)
	// Ensure the deleted host isn't returned
	for _, hostSet := range newHostSets.Items {
		assert.NotEqual(t, hostSet.Id, initialHostSets.Items[0].Id)
	}
}

// TestApiPaginateHostSets asserts that the API automatically paginates to retrieve
// all host sets in a single invocation.
func TestApiPaginateHostSets(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()
	sClient := scopes.NewClient(client)
	hsClient := hostsets.NewClient(client)
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, newOrgId)
		require.NoError(t, err)
	})
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)

	// Create enough host sets to overflow a single page.
	var hostSetIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostSetIds = append(hostSetIds, boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId))
	}

	// List host sets
	initialHostSets, err := hsClient.List(ctx, newHostCatalogId)
	require.NoError(t, err)

	var returnedIds []string
	for _, hostSet := range initialHostSets.Items {
		returnedIds = append(returnedIds, hostSet.Id)
	}

	require.Len(t, initialHostSets.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostSetIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialHostSets.ResponseType)
	assert.Empty(t, initialHostSets.RemovedIds)
	assert.NotEmpty(t, initialHostSets.ListToken)
	mapItems, ok := initialHostSets.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new host set and destroy one of the other host sets
	newHostSetId := boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId)
	_, err = hsClient.Delete(ctx, initialHostSets.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted host set
	newHostSets, err := hsClient.List(ctx, newHostCatalogId, hostsets.WithListToken(initialHostSets.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the host sets,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newHostSets.Items), 1)
	// The first item should be the most recently created, which
	// should be our new host set
	firstItem := newHostSets.Items[0]
	assert.Equal(t, newHostSetId, firstItem.Id)
	assert.Equal(t, "complete", newHostSets.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newHostSets.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newHostSets.RemovedIds, func(hostSetId string) bool {
		return hostSetId == initialHostSets.Items[0].Id
	}))
	assert.NotEmpty(t, newHostSets.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newHostSets.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
