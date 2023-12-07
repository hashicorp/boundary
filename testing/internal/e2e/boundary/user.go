// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewUserCli creates a new user using the Go api.
// Returns the id of the new user
func CreateNewUserApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) string {
	uClient := users.NewClient(client)
	newUserResult, err := uClient.Create(ctx, scopeId)
	require.NoError(t, err)

	newUserId := newUserResult.Item.Id
	t.Logf("Created User: %s", newUserId)
	return newUserId
}

// CreateNewUserCli creates a new user using the cli.
// Returns the id of the new user
func CreateNewUserCli(t testing.TB, ctx context.Context, scopeId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "create",
			"-scope-id", scopeId,
			"-name", "e2e User",
			"-description", "e2e User",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newUserResult users.UserCreateResult
	err := json.Unmarshal(output.Stdout, &newUserResult)
	require.NoError(t, err)

	newUserId := newUserResult.Item.Id
	t.Logf("Created User: %s", newUserId)
	return newUserId
}

// SetAccountToUserCli sets an account to a the specified user using the cli.
func SetAccountToUserCli(t testing.TB, ctx context.Context, userId string, accountId string) {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "set-accounts",
			"-id", userId,
			"-account", accountId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
