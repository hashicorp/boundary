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
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateHostCatalogs asserts that the CLI automatically paginates to retrieve
// all host catalogs in a single invocation.
func TestCliPaginateHostCatalogs(t *testing.T) {
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

	// Create enough host catalogs to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var hostCatalogIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostCatalogIds = append(hostCatalogIds, boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId))
	}

	// List host catalogs
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialHostCatalogs hostcatalogs.HostCatalogListResult
	err = json.Unmarshal(output.Stdout, &initialHostCatalogs)
	require.NoError(t, err)

	var returnedIds []string
	for _, hostCatalog := range initialHostCatalogs.Items {
		returnedIds = append(returnedIds, hostCatalog.Id)
	}

	require.Len(t, initialHostCatalogs.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostCatalogIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialHostCatalogs.ResponseType)
	assert.Empty(t, initialHostCatalogs.RemovedIds)
	assert.Empty(t, initialHostCatalogs.ListToken)

	// Create a new host catalog and destroy one of the other host catalogs
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "delete",
			"-id", initialHostCatalogs.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new host catalog but not the deleted host catalog
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-catalogs", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newHostCatalogs hostcatalogs.HostCatalogListResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogs)
	require.NoError(t, err)

	require.Len(t, newHostCatalogs.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new host catalog
	firstItem := newHostCatalogs.Items[0]
	assert.Equal(t, newHostCatalogId, firstItem.Id)
	assert.Empty(t, newHostCatalogs.ResponseType)
	assert.Empty(t, newHostCatalogs.RemovedIds)
	assert.Empty(t, newHostCatalogs.ListToken)
	// Ensure the deleted host isn't returned
	for _, hostCatalog := range newHostCatalogs.Items {
		assert.NotEqual(t, hostCatalog.Id, initialHostCatalogs.Items[0].Id)
	}
}

// TestApiPaginateHostCatalogs asserts that the API automatically paginates to retrieve
// all host catalogs in a single invocation.
func TestApiPaginateHostCatalogs(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()
	sClient := scopes.NewClient(client)
	hcClient := hostcatalogs.NewClient(client)
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, newOrgId)
		require.NoError(t, err)
	})
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)

	// Create enough host catalogs to overflow a single page.
	var hostCatalogIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostCatalogIds = append(hostCatalogIds, boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId))
	}

	// List host catalogs
	initialHostCatalogs, err := hcClient.List(ctx, newProjectId)
	require.NoError(t, err)

	var returnedIds []string
	for _, hostCatalog := range initialHostCatalogs.Items {
		returnedIds = append(returnedIds, hostCatalog.Id)
	}

	require.Len(t, initialHostCatalogs.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostCatalogIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialHostCatalogs.ResponseType)
	assert.Empty(t, initialHostCatalogs.RemovedIds)
	assert.NotEmpty(t, initialHostCatalogs.ListToken)
	mapItems, ok := initialHostCatalogs.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new host catalog and destroy one of the other host catalogs
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	_, err = hcClient.Delete(ctx, initialHostCatalogs.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted host catalog
	newHostCatalogs, err := hcClient.List(ctx, newProjectId, hostcatalogs.WithListToken(initialHostCatalogs.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the host catalogs,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newHostCatalogs.Items), 1)
	// The first item should be the most recently created, which
	// should be our new host catalog
	firstItem := newHostCatalogs.Items[0]
	assert.Equal(t, newHostCatalogId, firstItem.Id)
	assert.Equal(t, "complete", newHostCatalogs.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newHostCatalogs.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newHostCatalogs.RemovedIds, func(hostCatalogId string) bool {
		return hostCatalogId == initialHostCatalogs.Items[0].Id
	}))
	assert.NotEmpty(t, newHostCatalogs.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newHostCatalogs.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
