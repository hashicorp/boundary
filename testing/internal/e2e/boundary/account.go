// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateNewAccountApi creates a new account using the Go api.
// Returns the id of the new account as well as the password that was generated
func CreateNewAccountApi(t testing.TB, ctx context.Context, client *api.Client, loginName string) (accountId string, password string) {
	c, err := LoadConfig()
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
	return
}

// CreateNewAccountCli creates a new account using the cli.
// Returns the id of the new account as well as the password that was generated
func CreateNewAccountCli(t testing.TB, ctx context.Context, authMethodId string, loginName string) (string, string) {
	password, err := base62.Random(16)
	require.NoError(t, err)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts", "create", "password",
			"-auth-method-id", authMethodId,
			"-login-name", loginName,
			"-password", "env://E2E_TEST_ACCOUNT_PASSWORD",
			"-name", "e2e Account "+loginName,
			"-description", "e2e",
			"-format", "json",
		),
		e2e.WithEnv("E2E_TEST_ACCOUNT_PASSWORD", password),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAccountResult accounts.AccountCreateResult
	err = json.Unmarshal(output.Stdout, &newAccountResult)
	require.NoError(t, err)

	newAccountId := newAccountResult.Item.Id
	t.Logf("Created Account: %s", newAccountId)
	return newAccountId, password
}
