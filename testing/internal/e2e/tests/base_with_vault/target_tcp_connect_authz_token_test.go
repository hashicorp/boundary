// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetVaultConnectTargetWithAuthzToken uses the boundary and vault clis to add secrets
// management for a target. The test sets up vault as a credential store, creates a set of
// credentials in vault to be attached to a target, and attempts to connect to that target (with the
// authz-token option) using those credentials.
func TestCliTcpTargetVaultConnectTargetWithAuthzToken(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Configure vault
	boundaryPolicyName, kvPolicyFilePath := vault.Setup(t)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", boundaryPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", fmt.Sprintf("-path=%s", c.VaultSecretPath), "kv-v2"),
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
	kvPolicyName := vault.WritePolicy(t, ctx, kvPolicyFilePath)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", kvPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Log("Created Vault Credential")

	// Create vault token for boundary
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			fmt.Sprintf("-policy=%s", boundaryPolicyName),
			fmt.Sprintf("-policy=%s", kvPolicyName),
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
	newCredentialStoreId := boundary.CreateNewCredentialStoreVaultCli(t, ctx, newProjectId, c.VaultAddr, credStoreToken)

	// Create a credential library
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-libraries", "create", "vault",
			"-credential-store-id", newCredentialStoreId,
			"-vault-path", fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
			"-name", "e2e Automated Test Vault Credential Library",
			"-credential-type", "ssh_private_key",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialLibraryResult credentiallibraries.CredentialLibraryCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialLibraryResult)
	require.NoError(t, err)
	newCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newCredentialLibraryId)

	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialLibraryId)

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", newTargetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	newSessionAuthorization := newSessionAuthorizationResult.Item
	retrievedUser, ok := newSessionAuthorization.Credentials[0].Credential["username"].(string)
	require.True(t, ok)
	retrievedKey, ok := newSessionAuthorization.Credentials[0].Credential["private_key"].(string)
	require.True(t, ok)
	assert.Equal(t, c.TargetSshUser, retrievedUser)

	k, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	require.Equal(t, string(k), retrievedKey)
	t.Log("Successfully retrieved credentials for target")

	// Get auth token for session
	newAuthToken := newSessionAuthorizationResult.Item.AuthorizationToken

	// Create key file
	retrievedKeyPath := fmt.Sprintf("%s/%s", t.TempDir(), "target_private_key.pem")
	f, err := os.Create(retrievedKeyPath)
	require.NoError(t, err)
	_, err = f.WriteString(retrievedKey)
	require.NoError(t, err)
	err = os.Chmod(retrievedKeyPath, 0o400)
	require.NoError(t, err)

	// Connect to target and print host's IP address using retrieved credentials
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-authz-token", newAuthToken,
			"-exec", "/usr/bin/ssh", "--",
			"-l", retrievedUser,
			"-i", retrievedKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Successfully connected to target")
}
