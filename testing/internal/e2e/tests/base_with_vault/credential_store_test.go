// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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

	ctx := t.Context()
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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Configure vault
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		ctx := context.Background()
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
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credentials in vault
	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	passwordSecretName, passwordPolicyName, password := vault.CreateKvPasswordCredential(t, c.VaultSecretPath, c.TargetSshUser)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", passwordPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	domainSecretName, domainPolicyName, domainPassword := vault.CreateKvPasswordDomainCredential(t, c.VaultSecretPath, c.TargetSshUser, "domain.com")
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", domainPolicyName),
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
			"-policy="+privateKeyPolicyName,
			"-policy="+passwordPolicyName,
			"-policy="+domainPolicyName,
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
	storeId, err := boundary.CreateCredentialStoreVaultCli(t, ctx, projectId, c.VaultAddr, credStoreToken)
	require.NoError(t, err)

	// Create a credential library for the private key
	privateKeyCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		storeId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
		"ssh_private_key",
	)
	require.NoError(t, err)

	// Create a credential library for the password
	passwordCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		storeId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, passwordSecretName),
		"username_password",
	)
	require.NoError(t, err)

	// Create a credential library for the Domain
	domainCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		storeId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, domainSecretName),
		"username_password_domain",
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
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, privateKeyCredentialLibraryId)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, passwordCredentialLibraryId)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, domainCredentialLibraryId)
	require.NoError(t, err)

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", targetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	newSessionAuthorization := newSessionAuthorizationResult.Item
	require.Len(t, newSessionAuthorization.Credentials, 3)

	for _, v := range newSessionAuthorization.Credentials {
		switch v.CredentialSource.CredentialType {
		case "ssh_private_key":
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedKey, ok := v.Credential["private_key"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)

			keyData, err := os.ReadFile(c.TargetSshKeyPath)
			require.NoError(t, err)
			require.Equal(t, string(keyData), retrievedKey)
			t.Log("Successfully retrieved private key credentials for target")
		case "username_password":
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, password, retrievedPassword)
			t.Log("Successfully retrieved password credentials for target")
		case "username_password_domain":
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			retrievedDomain, ok := v.Credential["domain"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, domainPassword, retrievedPassword)
			assert.Equal(t, "domain.com", retrievedDomain)
			t.Log("Successfully retrieved username/password/domain credentials for target")
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
	ctx := t.Context()

	targetPort, err := strconv.ParseUint(c.TargetPort, 10, 32)
	require.NoError(t, err)

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
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
	targetId, err := boundary.CreateTargetApi(t, ctx, client, projectId, "tcp", targets.WithTcpTargetDefaultPort(uint32(targetPort)))
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetApi(t, ctx, client, targetId, hostSetId)
	require.NoError(t, err)

	// Configure vault
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credentials in vault
	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	passwordSecretName, passwordPolicyName, password := vault.CreateKvPasswordCredential(t, c.VaultSecretPath, c.TargetSshUser)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", passwordPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	domainSecretName, domainPolicyName, domainPassword := vault.CreateKvPasswordDomainCredential(t, c.VaultSecretPath, c.TargetSshUser, "domain.com")
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", domainPolicyName),
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
			"-policy="+privateKeyPolicyName,
			"-policy="+passwordPolicyName,
			"-policy="+domainPolicyName,
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

	// Create a credential library for the domain
	newCredentialLibraryResult, err = clClient.Create(ctx, "vault-generic", newCredentialStoreId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+domainSecretName),
		credentiallibraries.WithCredentialType("username_password_domain"),
	)
	require.NoError(t, err)
	newDomainCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newDomainCredentialLibraryId)

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

	// Add password brokered credentials to target
	_, err = tClient.AddCredentialSources(ctx, targetId, 0,
		targets.WithBrokeredCredentialSourceIds([]string{newDomainCredentialLibraryId}),
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	// Get credentials for target
	newSessionAuthorizationResult, err := tClient.AuthorizeSession(ctx, targetId)
	require.NoError(t, err)
	newSessionAuthorization := newSessionAuthorizationResult.Item
	require.Len(t, newSessionAuthorization.Credentials, 3)

	for _, v := range newSessionAuthorization.Credentials {
		switch v.CredentialSource.CredentialType {
		case "ssh_private_key":
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

		case "username_password":
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, password, retrievedPassword)
			t.Log("Successfully retrieved password credentials for target")
		case "username_password_domain":
			retrievedUser, ok := v.Credential["username"].(string)
			require.True(t, ok)
			retrievedPassword, ok := v.Credential["password"].(string)
			require.True(t, ok)
			retrievedDomain, ok := v.Credential["domain"].(string)
			require.True(t, ok)
			assert.Equal(t, c.TargetSshUser, retrievedUser)
			assert.Equal(t, domainPassword, retrievedPassword)
			assert.Equal(t, "domain.com", retrievedDomain)
			t.Log("Successfully retrieved username/password/domain credentials for target")

		}
	}
}
