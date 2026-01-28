// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

const testAccountName = "test-account"

// TestUserIsLoggedOutWhenAuthTokenIsDeletedCli validates that a user
// gets logged out if admin deletes its auth-token.
// The test authenticates a new user and verifies that it can perform
// operations requiring to be logged in (e.g. 'boundary auth-tokens list').
// Then the test deletes the user's auth-token by admin and verifies that
// the user cannot perform operations requiring to be logged in anymore.
func TestUserIsLoggedOutWhenAuthTokenIsDeletedCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	accountid, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, testAccountName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountid),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountid)
	require.NoError(t, err)

	// Authenticate user and assign a name to its auth token
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, testAccountName, acctPassword,
		e2e.WithArgs("-token-name", testAccountName),
	)

	// As the user, execute the command requiring to be logged in.
	// Provide the user's token name to the command so that it is executed by the user, not admin
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", testAccountName,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// As admin, delete the user's auth token
	userAuthTokenID := boundary.GetAuthenticationTokenIdByTokenNameCli(t, ctx, testAccountName)
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "delete",
			"-id", userAuthTokenID,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Logf("Successfully deleted user auth-token: %s", userAuthTokenID)

	// As the user, try to execute the command requiring to be logged in again
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", testAccountName,
		),
	)

	// Expect error as the user got logged out
	require.Error(t, output.Err, fmt.Sprintf("User %q is still logged in", testAccountName))
	t.Log("Successfully verified that token name is invalid")
}
