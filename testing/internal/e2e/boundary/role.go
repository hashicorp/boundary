// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewRoleApi creates a new role using the Go api.
// Returns the id of the new role
func CreateNewRoleApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) string {
	rClient := roles.NewClient(client)
	newRoleResult, err := rClient.Create(ctx, scopeId)
	require.NoError(t, err)

	newRoleId := newRoleResult.Item.Id
	t.Logf("Created Role: %s", newRoleId)
	return newRoleId
}

// CreateNewRoleCli creates a new role using the cli.
// Returns the id of the new role.
func CreateNewRoleCli(t testing.TB, ctx context.Context, scopeId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "create",
			"-scope-id", scopeId,
			"-name", "e2e Role",
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newRoleResult roles.RoleCreateResult
	err := json.Unmarshal(output.Stdout, &newRoleResult)
	require.NoError(t, err)

	newRoleId := newRoleResult.Item.Id
	t.Logf("Created Role: %s", newRoleId)
	return newRoleId
}

// AddGrantToRoleCli adds a grant/permission to a role using the cli
func AddGrantToRoleCli(t testing.TB, ctx context.Context, roleId string, grant string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "add-grants",
			"-id", roleId,
			"-grant", grant,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}

// AddPrincipalToRoleCli adds a user/group to a role using the cli
func AddPrincipalToRoleCli(t testing.TB, ctx context.Context, roleId string, principal string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"roles", "add-principals",
			"-id", roleId,
			"-principal", principal,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
