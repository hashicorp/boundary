// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateUserApi creates a new user using the Go api.
// Returns the id of the new user
func CreateUserApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	uClient := users.NewClient(client)
	createUserResult, err := uClient.Create(ctx, scopeId, users.WithName(fmt.Sprintf("e2e User %s", name)))
	if err != nil {
		return "", err
	}

	userId := createUserResult.Item.Id
	t.Logf("Created User: %s", userId)
	return userId, nil
}

// CreateNewUserCli creates a new user using the cli.
// Returns the id of the new user
func CreateNewUserCli(t testing.TB, ctx context.Context, scopeId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "create",
			"-scope-id", scopeId,
			"-name", "e2e User",
			"-description", "e2e",
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
