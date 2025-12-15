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
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateCredentials asserts that the CLI automatically paginates to retrieve
// all credentials in a single invocation.
func TestCliPaginateCredentials(t *testing.T) {
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
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)

	// Create enough credentials to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	cClient := credentials.NewClient(client)
	var credentialIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := cClient.Create(
			ctx,
			"username_password",
			storeId,
			credentials.WithUsernamePasswordCredentialUsername("user"),
			credentials.WithUsernamePasswordCredentialPassword("password"),
		)
		require.NoError(t, err)
		credentialIds = append(
			credentialIds,
			resp.Item.Id,
		)
	}

	// List credentials
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "list",
			"-credential-store-id", storeId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialCredentials credentials.CredentialListResult
	err = json.Unmarshal(output.Stdout, &initialCredentials)
	require.NoError(t, err)

	var returnedIds []string
	for _, cred := range initialCredentials.Items {
		returnedIds = append(returnedIds, cred.Id)
	}

	require.Len(t, initialCredentials.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, credentialIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialCredentials.ResponseType)
	assert.Empty(t, initialCredentials.RemovedIds)
	assert.Empty(t, initialCredentials.ListToken)

	// Create a new credential and destroy one of the other credentials
	credentialId, err := boundary.CreateStaticCredentialUsernamePasswordCli(t, ctx, storeId, "user", "password")
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "delete",
			"-id", initialCredentials.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new credential but not the deleted credential
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "list",
			"-credential-store-id", storeId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newCredentials credentials.CredentialListResult
	err = json.Unmarshal(output.Stdout, &newCredentials)
	require.NoError(t, err)

	require.Len(t, newCredentials.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new credential
	firstItem := newCredentials.Items[0]
	assert.Equal(t, credentialId, firstItem.Id)
	assert.Empty(t, newCredentials.ResponseType)
	assert.Empty(t, newCredentials.RemovedIds)
	assert.Empty(t, newCredentials.ListToken)
	// Ensure the deleted credential isn't returned
	for _, credential := range newCredentials.Items {
		assert.NotEqual(t, credential.Id, initialCredentials.Items[0].Id)
	}
}

// TestApiPaginateCredentials asserts that the API automatically paginates to retrieve
// all Credentials in a single invocation.
func TestApiPaginateCredentials(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	cClient := credentials.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	storeId, err := boundary.CreateCredentialStoreStaticApi(t, ctx, client, projectId)
	require.NoError(t, err)

	// Create enough credentials to overflow a single page.
	var credentialIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := cClient.Create(
			ctx,
			"username_password",
			storeId,
			credentials.WithUsernamePasswordCredentialUsername("user"),
			credentials.WithUsernamePasswordCredentialPassword("password"),
		)
		require.NoError(t, err)
		credentialIds = append(
			credentialIds,
			resp.Item.Id,
		)
	}

	// List Credentials
	initialCredentials, err := cClient.List(ctx, storeId)
	require.NoError(t, err)

	var returnedIds []string
	for _, cred := range initialCredentials.Items {
		returnedIds = append(returnedIds, cred.Id)
	}

	require.Len(t, initialCredentials.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, credentialIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialCredentials.ResponseType)
	assert.Empty(t, initialCredentials.RemovedIds)
	assert.NotEmpty(t, initialCredentials.ListToken)
	mapItems, ok := initialCredentials.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new credential and destroy one of the other Credentials
	credentialId, err := boundary.CreateStaticCredentialPasswordApi(t, ctx, client, storeId, "user", "password")
	require.NoError(t, err)
	_, err = cClient.Delete(ctx, initialCredentials.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted credential
	newCredentials, err := cClient.List(ctx, storeId, credentials.WithListToken(initialCredentials.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the credentials,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newCredentials.Items), 1)
	// The first item should be the most recently created, which
	// should be our new credential
	firstItem := newCredentials.Items[0]
	assert.Equal(t, credentialId, firstItem.Id)
	assert.Equal(t, "complete", newCredentials.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newCredentials.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newCredentials.RemovedIds, func(credentialId string) bool {
		return credentialId == initialCredentials.Items[0].Id
	}))
	assert.NotEmpty(t, newCredentials.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newCredentials.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
