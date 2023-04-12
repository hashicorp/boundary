// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

const testAccountName = "test-account"

// TestUserIsLoggedOutWhenAuthTokenIsDeletedCli validates auth-token deletion by admin
func TestUserIsLoggedOutWhenAuthTokenIsDeletedCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, bc.AuthMethodId, testAccountName)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", newAccountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		t.Logf("Successfully deleted account '%s'", newAccountId)
	})
	newUserId := boundary.CreateNewUserCli(t, ctx, "global")
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", newUserId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		t.Logf("Successfully deleted user '%s'", newUserId)
	})
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Authenticate user and assign a name to its auth token
	boundary.AuthenticateCli(t, context.Background(), bc.AuthMethodId, testAccountName, acctPassword,
		e2e.WithArgs("-token-name", testAccountName),
	)

	// Check if user is logged in
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", testAccountName,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Delete user's auth token by admin
	userAuthTokenID := boundary.GetAuthenticationTokenIdCli(t, ctx, testAccountName)
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "delete",
			"-id", userAuthTokenID,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Logf("Sucessfully deleted user auth-token: %s", userAuthTokenID)

	// Check if user is logged out
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", testAccountName,
		),
	)
	require.Error(t, output.Err, fmt.Sprintf("User '%s' is still logged in", testAccountName))
	t.Logf("User is logged out: %s", testAccountName)
}
