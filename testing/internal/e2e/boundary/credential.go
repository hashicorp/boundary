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

// CreateCredentialStoreStaticApi uses the Go api to create a new static credential store.
// Returns the id of the new credential store
func CreateCredentialStoreStaticApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	csClient := credentialstores.NewClient(client)
	newCredentialStoreResult, err := csClient.Create(
		ctx,
		"static",
		projectId,
		credentialstores.WithName(fmt.Sprintf("e2e Credential Store %s", name)),
	)
	if err != nil {
		return "", err
	}

	credentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", credentialStoreId)
	return credentialStoreId, nil
}

// CreateCredentialStoreVaultApi uses the API to create a Vault credential store
// Returns the id of the new credential store
func CreateCredentialStoreVaultApi(t testing.TB, ctx context.Context, client *api.Client, projectId string, vaultAddr string, vaultToken string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	c := credentialstores.NewClient(client)
	newCredentialStoreResult, err := c.Create(
		ctx, "vault", projectId,
		credentialstores.WithName("e2e Credential Store"),
		credentialstores.WithVaultCredentialStoreAddress(vaultAddr),
		credentialstores.WithVaultCredentialStoreToken(vaultToken),
		credentialstores.WithName(fmt.Sprintf("e2e Credential Store %s", name)),
	)
	if err != nil {
		return "", err
	}

	credentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", credentialStoreId)
	return credentialStoreId, nil
}

// CreateCredentialStoreVaultCli uses the cli to create a Vault credential store
// Returns the id of the new credential store
func CreateCredentialStoreVaultCli(t testing.TB, ctx context.Context, projectId string, vaultAddr string, vaultToken string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "create", "vault",
			"-scope-id", projectId,
			"-vault-address", vaultAddr,
			"-vault-token", vaultToken,
			"-name", fmt.Sprintf("e2e Credential Store %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialStoreResult)
	if err != nil {
		return "", err
	}

	credentialStoreId := createCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", credentialStoreId)
	return credentialStoreId, nil
}

// CreateCredentialStoreStaticCli uses the cli to create a new static credential store.
// Returns the id of the new credential store
func CreateCredentialStoreStaticCli(t testing.TB, ctx context.Context, projectId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "create", "static",
			"-scope-id", projectId,
			"-name", fmt.Sprintf("e2e Credential Store %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialStoreResult)
	if err != nil {
		return "", err
	}

	credentialStoreId := createCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", credentialStoreId)
	return credentialStoreId, nil
}

// CreateVaultGenericCredentialLibraryCli creates a vault-generic credential
// library using the cli
// Returns the id of the credential library or an error
func CreateVaultGenericCredentialLibraryCli(t testing.TB, ctx context.Context, credentialStoreId string, vaultPath string, credentialType string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

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
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialLibraryResult credentiallibraries.CredentialLibraryCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialLibraryResult)
	if err != nil {
		return "", err
	}

	credentialLibraryId := createCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", credentialLibraryId)
	return credentialLibraryId, nil
}

// CreateStaticCredentialPrivateKeyCli uses the cli to create a new private key credential in the
// provided static credential store.
// Returns the id of the new credential
func CreateStaticCredentialPrivateKeyCli(t testing.TB, ctx context.Context, credentialStoreId string, user string, filePath string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "ssh-private-key",
			"-credential-store-id", credentialStoreId,
			"-username", user,
			"-private-key", "file://"+filePath,
			"-name", fmt.Sprintf("e2e Credential %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialResult)
	if err != nil {
		return "", err
	}

	credentialId := createCredentialResult.Item.Id
	t.Logf("Created SSH Private Key Credentials: %s", credentialId)
	return credentialId, nil
}

// CreateStaticCredentialPasswordCli uses the cli to create a new password credential in the
// provided static credential store.
// Returns the id of the new credential
func CreateStaticCredentialPasswordCli(t testing.TB, ctx context.Context, credentialStoreId string, user string, password string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "username-password",
			"-credential-store-id", credentialStoreId,
			"-username", user,
			"-password", "env://E2E_CREDENTIALS_PASSWORD",
			"-name", fmt.Sprintf("e2e Credential %s", name),
			"-description", "e2e",
			"-format", "json",
		),
		e2e.WithEnv("E2E_CREDENTIALS_PASSWORD", password),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialsResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialsResult)
	if err != nil {
		return "", err
	}

	credentialId := createCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", credentialId)
	return credentialId, nil
}

// CreateStaticCredentialJsonCli uses the cli to create a new json credential in the provided
// static credential store.
// Returns the id of the new credential
func CreateStaticCredentialJsonCli(t testing.TB, ctx context.Context, credentialStoreId string, jsonFilePath string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "json",
			"-credential-store-id", credentialStoreId,
			"-object", "file://"+jsonFilePath,
			"-name", fmt.Sprintf("e2e Credential %s", name),
			"-description", "e2e",
			"-format", "json",
		),
	)
	if output.Err != nil {
		return "", fmt.Errorf("%w: %s", output.Err, string(output.Stderr))
	}

	var createCredentialsResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &createCredentialsResult)
	if err != nil {
		return "", err
	}

	credentialId := createCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", credentialId)
	return credentialId, nil
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
