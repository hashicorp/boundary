// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateAccountApi creates a new account using the Go api.
// Returns the id of the new account as well as the password that was generated
func CreateAccountApi(t testing.TB, ctx context.Context, client *api.Client, authMethodId string, loginName string) (string, string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", "", err
	}

	aClient := accounts.NewClient(client)
	password, err := base62.Random(16)
	if err != nil {
		return "", "", err
	}
	createAccountResult, err := aClient.Create(ctx, authMethodId,
		accounts.WithPasswordAccountLoginName(loginName),
		accounts.WithPasswordAccountPassword(password),
		accounts.WithName(fmt.Sprintf("e2e Account %s", name)),
	)
	if err != nil {
		return "", "", err
	}

	accountId := createAccountResult.Item.Id
	t.Logf("Create Account: %s", accountId)
	return accountId, password, nil
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
