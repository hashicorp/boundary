// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewGroupCli uses the cli to create a new group.
// Returns the id of the new group.
func CreateNewGroupCli(t testing.TB, ctx context.Context, scopeId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "create",
			"-scope-id", "global",
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newGroupResult groups.GroupCreateResult
	err := json.Unmarshal(output.Stdout, &newGroupResult)
	require.NoError(t, err)

	newGroupId := newGroupResult.Item.Id
	t.Logf("Created Group: %s", newGroupId)
	return newGroupId
}

// AddUserToGroup uses the cli to add a user to a group
func AddUserToGroup(t testing.TB, ctx context.Context, userId string, groupId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "add-members",
			"-id", groupId,
			"-member", userId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
