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
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateCredentialStores asserts that the CLI automatically paginates to retrieve
// all credential stores in a single invocation.
func TestCliPaginateCredentialStores(t *testing.T) {
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
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)

	// Create enough stores to overflow a single page.
	// Use the API to make creation faster.
	var storeIds []string
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	for i := 0; i < c.MaxPageSize+1; i++ {
		storeId, err := boundary.CreateCredentialStoreStaticApi(t, ctx, client, projectId)
		require.NoError(t, err)
		storeIds = append(storeIds, storeId)
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "list",
			"-scope-id", projectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialStores credentialstores.CredentialStoreListResult
	err = json.Unmarshal(output.Stdout, &initialStores)
	require.NoError(t, err)

	var returnedIds []string
	for _, store := range initialStores.Items {
		returnedIds = append(returnedIds, store.Id)
	}

	require.Len(t, initialStores.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, storeIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialStores.ResponseType)
	assert.Empty(t, initialStores.RemovedIds)
	assert.Empty(t, initialStores.ListToken)

	// Create a new store and destroy one of the other stores
	storeId, err := boundary.CreateCredentialStoreStaticApi(t, ctx, client, projectId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "delete",
			"-id", initialStores.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new store but not the deleted store
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "list",
			"-scope-id", projectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newStores credentialstores.CredentialStoreListResult
	err = json.Unmarshal(output.Stdout, &newStores)
	require.NoError(t, err)

	require.Len(t, newStores.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new store
	firstItem := newStores.Items[0]
	assert.Equal(t, storeId, firstItem.Id)
	assert.Empty(t, newStores.ResponseType)
	assert.Empty(t, newStores.RemovedIds)
	assert.Empty(t, newStores.ListToken)
	// Ensure the deleted store isn't returned
	for _, store := range newStores.Items {
		assert.NotEqual(t, store.Id, initialStores.Items[0].Id)
	}
}

// TestApiPaginateCredentialStores asserts that the API automatically paginates to retrieve
// all credential stores in a single invocation.
func TestApiPaginateCredentialStores(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	cClient := credentialstores.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)

	// Create enough stores to overflow a single page.
	var storeIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		storeId, err := boundary.CreateCredentialStoreStaticApi(t, ctx, client, projectId)
		require.NoError(t, err)
		storeIds = append(storeIds, storeId)
	}

	initialStores, err := cClient.List(ctx, projectId)
	require.NoError(t, err)

	var returnedIds []string
	for _, store := range initialStores.Items {
		returnedIds = append(returnedIds, store.Id)
	}

	require.Len(t, initialStores.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, storeIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialStores.ResponseType)
	assert.Empty(t, initialStores.RemovedIds)
	assert.NotEmpty(t, initialStores.ListToken)
	mapItems, ok := initialStores.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new store and destroy one of the other stores
	storeId, err := boundary.CreateCredentialStoreStaticApi(t, ctx, client, projectId)
	require.NoError(t, err)
	_, err = cClient.Delete(ctx, initialStores.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted store
	newStores, err := cClient.List(ctx, projectId, credentialstores.WithListToken(initialStores.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the stores,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newStores.Items), 1)
	// The first item should be the most recently created, which
	// should be our new store
	firstItem := newStores.Items[0]
	assert.Equal(t, storeId, firstItem.Id)
	assert.Equal(t, "complete", newStores.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newStores.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newStores.RemovedIds, func(storeId string) bool {
		return storeId == initialStores.Items[0].Id
	}))
	assert.NotEmpty(t, newStores.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newStores.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
