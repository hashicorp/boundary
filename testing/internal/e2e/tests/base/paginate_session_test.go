// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateSessions asserts that the CLI automatically paginates to retrieve
// all sessions in a single invocation. Canceling sessions is flaky so checking for
// canceled sessions is not included.
func TestCliPaginateSessions(t *testing.T) {
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
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	require.NoError(t, err)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Connect to targets to create a session
	// Create enough sessions to overflow a single page
	for i := 0; i < c.MaxPageSize+1; i++ {
		boundary.ConnectCli(t, ctx, newTargetId)
	}

	// List sessions recursively
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialSessions sessions.SessionListResult
	err = json.Unmarshal(output.Stdout, &initialSessions)
	require.NoError(t, err)

	require.Len(t, initialSessions.Items, c.MaxPageSize+1)
	// Note that none of these are returned to the CLI for now.
	assert.Empty(t, initialSessions.ResponseType)
	assert.Empty(t, initialSessions.RemovedIds)
	assert.Empty(t, initialSessions.ListToken)

	// Create a new session
	boundary.ConnectCli(t, ctx, newTargetId)

	// List again, should have the new session
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newSessions sessions.SessionListResult
	err = json.Unmarshal(output.Stdout, &newSessions)
	require.NoError(t, err)

	require.Len(t, newSessions.Items, c.MaxPageSize+2)
	assert.Empty(t, newSessions.ResponseType)
	assert.Empty(t, newSessions.RemovedIds)
	assert.Empty(t, newSessions.ListToken)
}

// TestApiPaginateSessions asserts that the API automatically paginates to retrieve
// all sessions in a single invocation. Canceling sessions is flaky so checking for
// canceled sessions is not included.
func TestApiPaginateSessions(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	sClient := sessions.NewClient(client)
	tClient := targets.NewClient(client)
	t.Cleanup(func() {
		ctx := context.Background()
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, newOrgId)
		require.NoError(t, err)
	})

	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	newHostSetId := boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId)
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetApi(t, ctx, client, newHostSetId, newHostId)
	require.NoError(t, err)
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, newHostSetId)

	// Connect to targets to create a session
	// Create enough sessions to overflow a single page
	for i := 0; i < c.MaxPageSize+1; i++ {
		// boundary.ConnectCli(t, ctx, newTargetId)
		_, err := tClient.AuthorizeSession(ctx, newTargetId)
		require.NoError(t, err)
	}

	// List sessions
	initialSessions, err := sClient.List(ctx, newProjectId)
	require.NoError(t, err)

	require.Len(t, initialSessions.Items, c.MaxPageSize+1)
	assert.Equal(t, "complete", initialSessions.ResponseType)
	assert.Empty(t, initialSessions.RemovedIds)
	assert.NotEmpty(t, initialSessions.ListToken)
	mapItems, ok := initialSessions.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new session
	boundary.ConnectCli(t, ctx, newTargetId)

	// List again, should have the new session
	newSessions, err := sClient.List(ctx, newProjectId, sessions.WithListToken(initialSessions.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the sessions,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newSessions.Items), 1)
	assert.Equal(t, "complete", newSessions.ResponseType)
	assert.NotEmpty(t, newSessions.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newSessions.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
