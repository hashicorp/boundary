// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateTargets asserts that the CLI automatically paginates to retrieve
// all targets in a single invocation.
func TestCliPaginateTargets(t *testing.T) {
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

	// Create enough targets to overflow a single page.
	// Use the API to make creation faster.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(c.TargetPort, 10, 32)
	require.NoError(t, err)
	var targetIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := tClient.Create(ctx, "tcp", projectId,
			targets.WithName("test-target-"+strconv.Itoa(i)),
			targets.WithTcpTargetDefaultPort(uint32(targetPort)),
			targets.WithAddress(c.TargetAddress),
		)
		require.NoError(t, err)
		targetIds = append(targetIds, resp.Item.Id)
	}

	// List targets recursively
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "list",
			"-scope-id", projectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialTargets targets.TargetListResult
	err = json.Unmarshal(output.Stdout, &initialTargets)
	require.NoError(t, err)
	var returnedIds []string
	for _, item := range initialTargets.Items {
		returnedIds = append(returnedIds, item.Id)
	}

	require.Len(t, initialTargets.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, targetIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	// Note that none of these are returned to the CLI for now.
	assert.Empty(t, initialTargets.ResponseType)
	assert.Empty(t, initialTargets.RemovedIds)
	assert.Empty(t, initialTargets.ListToken)

	// Create a new target and destroy one of the other targets
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, []target.Option{target.WithAddress(c.TargetAddress)})
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "delete",
			"-id", initialTargets.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new target but not the deleted target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "list",
			"-scope-id", projectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newTargets targets.TargetListResult
	err = json.Unmarshal(output.Stdout, &newTargets)
	require.NoError(t, err)

	require.Len(t, newTargets.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new target
	firstItem := newTargets.Items[0]
	assert.Equal(t, targetId, firstItem.Id)
	assert.Empty(t, newTargets.ResponseType)
	assert.Empty(t, newTargets.RemovedIds)
	assert.Empty(t, newTargets.ListToken)
	// Ensure the deleted targeted isn't returned
	for _, target := range newTargets.Items {
		assert.NotEqual(t, target.Id, initialTargets.Items[0].Id)
	}
}

// TestApiPaginateTargets asserts that the API automatically paginates to retrieve
// all targets in a single invocation.
func TestApiPaginateTargets(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	tClient := targets.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)

	// Create enough targets to overflow a single page.
	targetPort, err := strconv.ParseInt(c.TargetPort, 10, 32)
	require.NoError(t, err)
	var targetIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := tClient.Create(ctx, "tcp", projectId,
			targets.WithName("test-target-"+strconv.Itoa(i)),
			targets.WithTcpTargetDefaultPort(uint32(targetPort)),
			targets.WithAddress(c.TargetAddress),
		)
		require.NoError(t, err)
		targetIds = append(targetIds, resp.Item.Id)
	}

	// List targets recursively
	initialTargets, err := tClient.List(ctx, projectId)
	require.NoError(t, err)
	var returnedIds []string
	for _, item := range initialTargets.Items {
		returnedIds = append(returnedIds, item.Id)
	}

	require.Len(t, initialTargets.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, targetIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialTargets.ResponseType)
	assert.Empty(t, initialTargets.RemovedIds)
	assert.NotEmpty(t, initialTargets.ListToken)
	mapItems, ok := initialTargets.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new target and destroy one of the other targets
	newTargetResult, err := tClient.Create(ctx, "tcp", projectId,
		targets.WithName("test-target-"+strconv.Itoa(c.MaxPageSize+1)),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
		targets.WithAddress(c.TargetAddress),
	)
	require.NoError(t, err)
	_, err = tClient.Delete(ctx, initialTargets.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted target
	newTargets, err := tClient.List(ctx, projectId, targets.WithListToken(initialTargets.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the targets,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newTargets.Items), 1)
	// The first item should be the most recently created, which
	// should be our new target
	firstItem := newTargets.Items[0]
	assert.Equal(t, newTargetResult.Item.Id, firstItem.Id)
	assert.Equal(t, "complete", newTargets.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newTargets.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newTargets.RemovedIds, func(targetId string) bool {
		return targetId == initialTargets.Items[0].Id
	}))
	assert.NotEmpty(t, newTargets.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newTargets.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
