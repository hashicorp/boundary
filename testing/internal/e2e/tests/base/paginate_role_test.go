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
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateRoles asserts that the CLI automatically paginates to retrieve
// all roles in a single invocation.
func TestCliPaginateRoles(t *testing.T) {
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

	// Create enough roles to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	// Creating an org comes with two automatically created roles,
	// "Login and Default Grants" and "Administration", so we
	// need to remove them from the total role count.
	numPrecreatedRoles := 2
	var roleIds []string
	for i := 0; i < c.MaxPageSize+1-numPrecreatedRoles; i++ {
		roleId, err := boundary.CreateRoleApi(t, ctx, client, orgId)
		require.NoError(t, err)
		roleIds = append(roleIds, roleId)
	}

	// List roles
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialRoles roles.RoleListResult
	err = json.Unmarshal(output.Stdout, &initialRoles)
	require.NoError(t, err)

	var returnedIds []string
	// Ignore the two precreated roles, which will appear at the end
	for _, role := range initialRoles.Items[:len(initialRoles.Items)-numPrecreatedRoles] {
		returnedIds = append(returnedIds, role.Id)
	}

	require.Len(t, initialRoles.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, roleIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialRoles.ResponseType)
	assert.Empty(t, initialRoles.RemovedIds)
	assert.Empty(t, initialRoles.ListToken)

	// Create a new role and destroy one of the other roles
	roleId, err := boundary.CreateRoleApi(t, ctx, client, orgId)
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "delete",
			"-id", initialRoles.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new role but not the deleted role
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "list",
			"-scope-id", orgId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newRoles roles.RoleListResult
	err = json.Unmarshal(output.Stdout, &newRoles)
	require.NoError(t, err)

	require.Len(t, newRoles.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new role
	firstItem := newRoles.Items[0]
	assert.Equal(t, roleId, firstItem.Id)
	assert.Empty(t, newRoles.ResponseType)
	assert.Empty(t, newRoles.RemovedIds)
	assert.Empty(t, newRoles.ListToken)
	// Ensure the deleted role isn't returned
	for _, role := range newRoles.Items {
		assert.NotEqual(t, role.Id, initialRoles.Items[0].Id)
	}
}

// TestApiPaginateRoles asserts that the API automatically paginates to retrieve
// all roles in a single invocation.
func TestApiPaginateRoles(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	uClient := roles.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})

	// Create enough roles to overflow a single page.
	// Creating an org comes with two automatically created roles,
	// "Login and Default Grants" and "Administration", so we
	// need to remove them from the total role count.
	numPrecreatedRoles := 2
	var roleIds []string
	for i := 0; i < c.MaxPageSize+1-numPrecreatedRoles; i++ {
		roleId, err := boundary.CreateRoleApi(t, ctx, client, orgId)
		require.NoError(t, err)
		roleIds = append(roleIds, roleId)
	}

	// List roles
	initialRoles, err := uClient.List(ctx, orgId)
	require.NoError(t, err)

	var returnedIds []string
	// Ignore the two precreated roles, which will appear at the end
	for _, role := range initialRoles.Items[:len(initialRoles.Items)-numPrecreatedRoles] {
		returnedIds = append(returnedIds, role.Id)
	}

	require.Len(t, initialRoles.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, roleIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialRoles.ResponseType)
	assert.Empty(t, initialRoles.RemovedIds)
	assert.NotEmpty(t, initialRoles.ListToken)
	mapItems, ok := initialRoles.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new role and destroy one of the other roles
	roleId, err := boundary.CreateRoleApi(t, ctx, client, orgId)
	require.NoError(t, err)
	_, err = uClient.Delete(ctx, initialRoles.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted role
	newRoles, err := uClient.List(ctx, orgId, roles.WithListToken(initialRoles.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the roles,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newRoles.Items), 1)
	// The first item should be the most recently created, which
	// should be our new role
	firstItem := newRoles.Items[0]
	assert.Equal(t, roleId, firstItem.Id)
	assert.Equal(t, "complete", newRoles.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newRoles.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newRoles.RemovedIds, func(roleId string) bool {
		return roleId == initialRoles.Items[0].Id
	}))
	assert.NotEmpty(t, newRoles.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newRoles.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
