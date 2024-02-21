// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
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

// CreateNewCredentialStoreVaultApi uses the API to create a Vault credential store
// Returns the id of the new credential store
func CreateNewCredentialStoreVaultApi(t testing.TB, ctx context.Context, client *api.Client, projectId string, vaultAddr string, vaultToken string) string {
	c := credentialstores.NewClient(client)
	newCredentialStoreResult, err := c.Create(
		ctx, "vault", projectId,
		credentialstores.WithName("e2e Credential Store"),
		credentialstores.WithVaultCredentialStoreAddress(vaultAddr),
		credentialstores.WithVaultCredentialStoreToken(vaultToken),
	)
	require.NoError(t, err)
	newVaultCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newVaultCredentialStoreId)

	return newVaultCredentialStoreId
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
			"-description", "e2e",
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
			"-description", "e2e",
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

// CreateVaultGenericCredentialLibraryCli creates a vault-generic credential library using the cli
func CreateVaultGenericCredentialLibraryCli(t testing.TB, ctx context.Context, credentialStoreId string, vaultPath string, credentialType string) (string, error) {
	name, err := base62.Random(16)
	require.NoError(t, err)

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-libraries", "create", "vault-generic",
			"-credential-store-id", credentialStoreId,
			"-vault-path", vaultPath,
			"-credential-type", credentialType,
			"-name", fmt.Sprintf("e2e Credential Library %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%s", output.Stderr)
	}

	var newCredentialLibraryResult credentiallibraries.CredentialLibraryCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialLibraryResult)
	if err != nil {
		return "", err
	}
	credentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", credentialLibraryId)
	return credentialLibraryId, nil
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
			"-description", "e2e",
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
			"-description", "e2e",
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
			"-description", "e2e",
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

// CreateNewStaticCredentialPasswordApi uses the API to create a new password credential in the
// provided static credential store.
// Returns the id of the new credential
func CreateNewStaticCredentialPasswordApi(t testing.TB, ctx context.Context, client *api.Client, credentialStoreId string, user string, password string) string {
	c := credentials.NewClient(client)
	newCredentialsResult, err := c.Create(ctx, "username_password", credentialStoreId,
		credentials.WithUsernamePasswordCredentialUsername(user),
		credentials.WithUsernamePasswordCredentialPassword(password),
	)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", newCredentialsId)

	return newCredentialsId
}
