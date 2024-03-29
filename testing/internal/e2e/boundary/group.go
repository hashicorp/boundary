// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateGroupApi uses the API to create a new group.
// Returns the id of the new group.
func CreateGroupApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	gClient := groups.NewClient(client)
	newGroup, err := gClient.Create(ctx, scopeId, groups.WithName(fmt.Sprintf("e2e Group %s", name)))
	if err != nil {
		return "", err
	}

	groupId := newGroup.Item.Id
	t.Logf("Created Group: %s", groupId)
	return groupId, nil
}

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
