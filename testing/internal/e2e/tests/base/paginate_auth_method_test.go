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
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
