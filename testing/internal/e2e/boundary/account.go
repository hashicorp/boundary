package boundary

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateNewAccountApi creates a new account using the go api.
// Returns the id of the new account as well as the password that was generated
func CreateNewAccountApi(t testing.TB, ctx context.Context, client *api.Client, loginName string) (accountId string, password string) {
	c, err := loadConfig()
	require.NoError(t, err)

	aClient := accounts.NewClient(client)
	password, err = base62.Random(16)
	require.NoError(t, err)
	newAccountResult, err := aClient.Create(ctx, c.AuthMethodId,
		accounts.WithPasswordAccountLoginName(loginName),
		accounts.WithPasswordAccountPassword(password),
	)
	require.NoError(t, err)

	accountId = newAccountResult.Item.Id
	t.Logf("Create Account: %s", accountId)
	t.Cleanup(func() {
		_, err := aClient.Delete(ctx, accountId)
		require.NoError(t, err)
	})

	return
}

// CreateNewAccountCli creates a new account using the cli.
// Returns the id of the new account as well as the password that was generated
func CreateNewAccountCli(t testing.TB, loginName string) (string, string) {
	c, err := loadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	password, err := base62.Random(16)
	require.NoError(t, err)
	os.Setenv("E2E_TEST_ACCOUNT_PASSWORD", password)
	output := e2e.RunCommand(ctx, "boundary", "accounts", "create", "password",
		"-auth-method-id", c.AuthMethodId,
		"-login-name", loginName,
		"-password", "env://E2E_TEST_ACCOUNT_PASSWORD",
		"-name", "e2e Account "+loginName,
		"-description", "e2e Account",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAccountResult accounts.AccountCreateResult
	err = json.Unmarshal(output.Stdout, &newAccountResult)
	require.NoError(t, err)

	newAccountId := newAccountResult.Item.Id
	t.Cleanup(func() {
		AuthenticateAdminCli(t)
		output := e2e.RunCommand(ctx, "boundary", "accounts", "delete", "-id", newAccountId)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	t.Logf("Created Account: %s", newAccountId)

	return newAccountId, password
}
