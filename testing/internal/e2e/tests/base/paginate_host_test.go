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
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateHosts asserts that the CLI automatically paginates to retrieve
// all hosts in a single invocation.
func TestCliPaginateHosts(t *testing.T) {
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

	// Create enough hosts to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var hostIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostIds = append(hostIds, boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetAddress))
	}

	// List hosts
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"hosts", "list",
			"-host-catalog-id", newHostCatalogId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialHosts hosts.HostListResult
	err = json.Unmarshal(output.Stdout, &initialHosts)
	require.NoError(t, err)

	var returnedIds []string
	for _, host := range initialHosts.Items {
		returnedIds = append(returnedIds, host.Id)
	}

	require.Len(t, initialHosts.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialHosts.ResponseType)
	assert.Empty(t, initialHosts.RemovedIds)
	assert.Empty(t, initialHosts.ListToken)

	// Create a new host and destroy one of the other hosts
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetAddress)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"hosts", "delete",
			"-id", initialHosts.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new host but not the deleted host
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"hosts", "list",
			"-host-catalog-id", newHostCatalogId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newHosts hosts.HostListResult
	err = json.Unmarshal(output.Stdout, &newHosts)
	require.NoError(t, err)

	require.Len(t, newHosts.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new host
	firstItem := newHosts.Items[0]
	assert.Equal(t, newHostId, firstItem.Id)
	assert.Empty(t, newHosts.ResponseType)
	assert.Empty(t, newHosts.RemovedIds)
	assert.Empty(t, newHosts.ListToken)
	// Ensure the deleted host isn't returned
	for _, host := range newHosts.Items {
		assert.NotEqual(t, host.Id, initialHosts.Items[0].Id)
	}
}

// TestApiPaginateHosts asserts that the API automatically paginates to retrieve
// all hosts in a single invocation.
func TestApiPaginateHosts(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()
	sClient := scopes.NewClient(client)
	hClient := hosts.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, projectId)

	// Create enough hosts to overflow a single page.
	var hostIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		hostIds = append(hostIds, boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetAddress))
	}

	// List hosts
	initialHosts, err := hClient.List(ctx, newHostCatalogId)
	require.NoError(t, err)

	var returnedIds []string
	for _, host := range initialHosts.Items {
		returnedIds = append(returnedIds, host.Id)
	}

	require.Len(t, initialHosts.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, hostIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialHosts.ResponseType)
	assert.Empty(t, initialHosts.RemovedIds)
	assert.NotEmpty(t, initialHosts.ListToken)
	mapItems, ok := initialHosts.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new host and destroy one of the other hosts
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetAddress)
	_, err = hClient.Delete(ctx, initialHosts.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted host
	newHosts, err := hClient.List(ctx, newHostCatalogId, hosts.WithListToken(initialHosts.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the hosts,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newHosts.Items), 1)
	// The first item should be the most recently created, which
	// should be our new host
	firstItem := newHosts.Items[0]
	assert.Equal(t, newHostId, firstItem.Id)
	assert.Equal(t, "complete", newHosts.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newHosts.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newHosts.RemovedIds, func(hostId string) bool {
		return hostId == initialHosts.Items[0].Id
	}))
	assert.NotEmpty(t, newHosts.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newHosts.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
