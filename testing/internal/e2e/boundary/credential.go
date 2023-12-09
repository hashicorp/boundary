// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewCredentialStoreStaticApi uses the Go api to create a new static credential store.
// Returns the id of the new credential store
func CreateNewCredentialStoreStaticApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) string {
	csClient := credentialstores.NewClient(client)
	newCredentialStoreResult, err := csClient.Create(ctx, "static", projectId)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	return newCredentialStoreId
}

// CreateNewCredentialStoreVaultCli uses the cli to create a Vault credential store
// Returns the id of the new credential store
func CreateNewCredentialStoreVaultCli(t testing.TB, ctx context.Context, projectId string, vaultAddr string, vaultToken string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "create", "vault",
			"-scope-id", projectId,
			"-vault-address", vaultAddr,
			"-vault-token", vaultToken,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialStoreResult)
	require.NoError(t, err)
	newVaultCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newVaultCredentialStoreId)

	return newVaultCredentialStoreId
}

// CreateNewCredentialStoreStaticCli uses the cli to create a new static credential store.
// Returns the id of the new credential store
func CreateNewCredentialStoreStaticCli(t testing.TB, ctx context.Context, projectId string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "create", "static",
			"-scope-id", projectId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialStoreResult)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	return newCredentialStoreId
}

// CreateNewStaticCredentialPrivateKeyCli uses the cli to create a new private key credential in the
// provided static credential store.
// Returns the id of the new credential
func CreateNewStaticCredentialPrivateKeyCli(t testing.TB, ctx context.Context, credentialStoreId string, user string, filePath string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "ssh-private-key",
			"-credential-store-id", credentialStoreId,
			"-username", user,
			"-private-key", "file://"+filePath,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialsResult credentials.CredentialCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialsResult)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created SSH Private Key Credentials: %s", newCredentialsId)

	return newCredentialsId
}

// CreateNewStaticCredentialPasswordCli uses the cli to create a new password credential in the
// provided static credential store.
// Returns the id of the new credential
func CreateNewStaticCredentialPasswordCli(t testing.TB, ctx context.Context, credentialStoreId string, user string, password string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "username-password",
			"-credential-store-id", credentialStoreId,
			"-username", user,
			"-password", "env://E2E_CREDENTIALS_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_CREDENTIALS_PASSWORD", password),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialsResult credentials.CredentialCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialsResult)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", newCredentialsId)

	return newCredentialsId
}

// CreateNewStaticCredentialJsonCli uses the cli to create a new json credential in the provided
// static credential store.
// Returns the id of the new credential
func CreateNewStaticCredentialJsonCli(t testing.TB, ctx context.Context, credentialStoreId string, jsonFilePath string) string {
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "json",
			"-credential-store-id", credentialStoreId,
			"-object", "file://"+jsonFilePath,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialsResult credentials.CredentialCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialsResult)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", newCredentialsId)

	return newCredentialsId
}
