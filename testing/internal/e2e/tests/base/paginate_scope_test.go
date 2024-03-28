// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateScopes asserts that the CLI automatically paginates to retrieve
// all scopes in a single invocation.
func TestCliPaginateScopes(t *testing.T) {
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

	// Create enough scopes to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	var scopeIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		scopeIds = append(scopeIds, boundary.CreateNewProjectApi(t, ctx, client, newOrgId))
	}

	// List scopes
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list",
			"-scope-id", newOrgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialScopes scopes.ScopeListResult
	err = json.Unmarshal(output.Stdout, &initialScopes)
	require.NoError(t, err)

	var returnedIds []string
	for _, scope := range initialScopes.Items {
		returnedIds = append(returnedIds, scope.Id)
	}

	require.Len(t, initialScopes.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, scopeIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialScopes.ResponseType)
	assert.Empty(t, initialScopes.RemovedIds)
	assert.Empty(t, initialScopes.ListToken)

	// Create a new scope and destroy one of the other scopes
	newScopeId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "delete",
			"-id", initialScopes.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new scope but not the deleted scope
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list",
			"-scope-id", newOrgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newScopes scopes.ScopeListResult
	err = json.Unmarshal(output.Stdout, &newScopes)
	require.NoError(t, err)

	require.Len(t, newScopes.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new scope
	firstItem := newScopes.Items[0]
	assert.Equal(t, newScopeId, firstItem.Id)
	assert.Empty(t, newScopes.ResponseType)
	assert.Empty(t, newScopes.RemovedIds)
	assert.Empty(t, newScopes.ListToken)
	// Ensure the deleted scope isn't returned
	for _, scope := range newScopes.Items {
		assert.NotEqual(t, scope.Id, initialScopes.Items[0].Id)
	}
}

// TestApiPaginateScopes asserts that the API automatically paginates to retrieve
// all scopes in a single invocation.
func TestApiPaginateScopes(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()
	sClient := scopes.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	// Create enough scopes to overflow a single page.
	var scopeIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		scopeIds = append(scopeIds, boundary.CreateNewProjectApi(t, ctx, client, orgId))
	}

	// List scopes
	initialScopes, err := sClient.List(ctx, orgId)
	require.NoError(t, err)

	var returnedIds []string
	for _, scope := range initialScopes.Items {
		returnedIds = append(returnedIds, scope.Id)
	}

	require.Len(t, initialScopes.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, scopeIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialScopes.ResponseType)
	assert.Empty(t, initialScopes.RemovedIds)
	assert.NotEmpty(t, initialScopes.ListToken)
	mapItems, ok := initialScopes.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Creating or deleting a scope changes the grants, so we can't test that here
}
