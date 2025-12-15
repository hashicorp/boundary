// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"strconv"
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
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Connect to targets to create a session
	// Create enough sessions to overflow a single page
	for i := 0; i < c.MaxPageSize+1; i++ {
		boundary.ConnectCli(t, ctx, targetId)
	}

	// List sessions recursively
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"-scope-id", projectId,
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
	boundary.ConnectCli(t, ctx, targetId)

	// List again, should have the new session
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"-scope-id", projectId,
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
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	sClient := sessions.NewClient(client)
	tClient := targets.NewClient(client)
	t.Cleanup(func() {
		ctx := context.Background()
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	targetPort, err := strconv.ParseUint(c.TargetPort, 10, 32)
	require.NoError(t, err)

	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogApi(t, ctx, client, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetApi(t, ctx, client, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostApi(t, ctx, client, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetApi(t, ctx, client, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetApi(t, ctx, client, projectId, "tcp", targets.WithTcpTargetDefaultPort(uint32(targetPort)))
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetApi(t, ctx, client, targetId, hostSetId)
	require.NoError(t, err)

	// Connect to targets to create a session
	// Create enough sessions to overflow a single page
	for i := 0; i < c.MaxPageSize+1; i++ {
		// boundary.ConnectCli(t, ctx, newTargetId)
		_, err := tClient.AuthorizeSession(ctx, targetId)
		require.NoError(t, err)
	}

	// List sessions
	initialSessions, err := sClient.List(ctx, projectId)
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
	boundary.ConnectCli(t, ctx, targetId)

	// List again, should have the new session
	newSessions, err := sClient.List(ctx, projectId, sessions.WithListToken(initialSessions.ListToken))
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
