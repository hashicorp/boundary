package static_test

import (
	"context"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserIsLoggedOutWhenAuthTokenIsDeletedCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	acctName := "test-account1"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, bc.AuthMethodId, acctName)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", newAccountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newUserId := boundary.CreateNewUserCli(t, ctx, "global")
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", newUserId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Authenticate user and assign a name to its auth token
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "password",
			"-addr", bc.Address,
			"-auth-method-id", bc.AuthMethodId,
			"-login-name", acctName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-token-name", acctName,
		),
		e2e.WithEnv("E2E_TEST_BOUNDARY_PASSWORD", acctPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	userAuthTokenID := boundary.GetAuthenticationTokenIDCli(t, ctx, acctName, acctPassword)

	// Check if user is logged in
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", acctName,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Delete user's auth token by admin
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "delete",
			"-id", userAuthTokenID,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Check if user is NOT logged in
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-token-name", acctName,
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
}
