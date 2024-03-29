// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliVaultCredentialStore uses the cli to perform a number of credential store operations with
// vault
func TestCliVaultCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Configure vault
	boundaryPolicyName, kvPolicyFilePath := vault.Setup(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", boundaryPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credentials in vault
	privateKeySecretName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath, kvPolicyFilePath)
	passwordSecretName, password := vault.CreateKvPasswordCredential(t, c.VaultSecretPath, c.TargetSshUser, kvPolicyFilePath)
	kvPolicyName := vault.WritePolicy(t, ctx, kvPolicyFilePath)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", kvPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Log("Created Vault Credentials")

	// Create vault token for boundary
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+kvPolicyName,
			"-orphan=true",
			"-period=20m",
			"-renewable=true",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult vault.CreateTokenResponse
	err = json.Unmarshal(output.Stdout, &tokenCreateResult)
	require.NoError(t, err)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")

	// Create a credential store
	newCredentialStoreId := boundary.CreateNewCredentialStoreVaultCli(t, ctx, projectId, c.VaultAddr, credStoreToken)

	// Create a credential library for the private key
	newPrivateKeyCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		newCredentialStoreId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
		"ssh_private_key",
	)
	require.NoError(t, err)

	// Create a credential library for the password
	newPasswordCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		newCredentialStoreId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, passwordSecretName),
		"username_password",
	)
	require.NoError(t, err)

	// Get credentials for target (expect empty)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", targetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)
	require.True(t, newSessionAuthorizationResult.Item.Credentials == nil)

	// Add credentials to target
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, newPrivateKeyCredentialLibraryId)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, newPasswordCredentialLibraryId)
	require.NoError(t, err)

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", targetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	newSessionAuthorization := newSessionAuthorizationResult.Item
	require.Len(t, newSessionAuthorization.Credentials, 2)

	for _, v := range newSessionAuthorization.Credentials {
		if v.CredentialSource.CredentialType == "ssh_private_key" {
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedKey, ok := v.Credential["private_key"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)

			keyData, err := os.ReadFile(c.TargetSshKeyPath)
			require.NoError(t, err)
			require.Equal(t, string(keyData), retrievedKey)
			t.Log("Successfully retrieved private key credentials for target")
		} else if v.CredentialSource.CredentialType == "username_password" {
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, password, retrievedPassword)
			t.Log("Successfully retrieved password credentials for target")
		}
	}
}

// TestApiVaultCredentialStore uses the Go api to perform a number of credential store operations
// with vault
func TestApiVaultCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogApi(t, ctx, client, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetApi(t, ctx, client, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostApi(t, ctx, client, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetApi(t, ctx, client, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetApi(t, ctx, client, projectId, c.TargetPort)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetApi(t, ctx, client, targetId, hostSetId)
	require.NoError(t, err)

	// Configure vault
	boundaryPolicyName, kvPolicyFilePath := vault.Setup(t, "testdata/boundary-controller-policy.hcl")
	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credential in vault
	privateKeySecretName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath, kvPolicyFilePath)
	passwordSecretName, password := vault.CreateKvPasswordCredential(t, c.VaultSecretPath, c.TargetSshUser, kvPolicyFilePath)
	kvPolicyName := vault.WritePolicy(t, ctx, kvPolicyFilePath)
	t.Log("Created Vault Credentials")

	// Create vault token for boundary
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+kvPolicyName,
			"-orphan=true",
			"-period=20m",
			"-renewable=true",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult vault.CreateTokenResponse
	err = json.Unmarshal(output.Stdout, &tokenCreateResult)
	require.NoError(t, err)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")

	// Create a credential store
	csClient := credentialstores.NewClient(client)
	newCredentialStoreResult, err := csClient.Create(ctx, "vault", projectId,
		credentialstores.WithVaultCredentialStoreAddress(c.VaultAddr),
		credentialstores.WithVaultCredentialStoreToken(credStoreToken),
	)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	// Create a credential library for the private key
	clClient := credentiallibraries.NewClient(client)
	newCredentialLibraryResult, err := clClient.Create(ctx, "vault-generic", newCredentialStoreId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+privateKeySecretName),
		credentiallibraries.WithCredentialType("ssh_private_key"),
	)
	require.NoError(t, err)
	newPrivateKeyCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newPrivateKeyCredentialLibraryId)

	// Create a credential library for the password
	newCredentialLibraryResult, err = clClient.Create(ctx, "vault-generic", newCredentialStoreId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+passwordSecretName),
		credentiallibraries.WithCredentialType("username_password"),
	)
	require.NoError(t, err)
	newPasswordCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newPasswordCredentialLibraryId)

	// Add private key brokered credentials to target
	tClient := targets.NewClient(client)
	_, err = tClient.AddCredentialSources(ctx, targetId, 0,
		targets.WithBrokeredCredentialSourceIds([]string{newPrivateKeyCredentialLibraryId}),
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	// Add password brokered credentials to target
	_, err = tClient.AddCredentialSources(ctx, targetId, 0,
		targets.WithBrokeredCredentialSourceIds([]string{newPasswordCredentialLibraryId}),
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	// Get credentials for target
	newSessionAuthorizationResult, err := tClient.AuthorizeSession(ctx, targetId)
	require.NoError(t, err)
	newSessionAuthorization := newSessionAuthorizationResult.Item
	require.Len(t, newSessionAuthorization.Credentials, 2)

	for _, v := range newSessionAuthorization.Credentials {
		if v.CredentialSource.CredentialType == "ssh_private_key" {
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)

			retrievedKey, ok := v.Credential["private_key"].(string)
			require.True(t, ok)
			k, err := os.ReadFile(c.TargetSshKeyPath)
			require.NoError(t, err)
			keysMatch := string(k) == retrievedKey // This is done to prevent printing out key info
			require.True(t, keysMatch, "Key retrieved from vault does not match expected value")
			t.Log("Successfully retrieved credentials for target")
		} else if v.CredentialSource.CredentialType == "username_password" {
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, password, retrievedPassword)
			t.Log("Successfully retrieved password credentials for target")
		}
	}
}
