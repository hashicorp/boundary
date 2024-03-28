// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetVaultGenericConnectTargetWithSsh uses the boundary and vault clis to add secrets management for a
// target. The test sets up vault as a credential store, creates a set of credentials in vault to be
// attached to a target, and attempts to connect to that target (with the ssh option) using those
// credentials.
func TestCliTcpTargetVaultGenericConnectTargetWithSsh(t *testing.T) {
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
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Configure vault
	boundaryPolicyName, kvPolicyFilePath := vault.Setup(t, "testdata/boundary-controller-policy.hcl")
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
	newCredentialLibraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		newCredentialStoreId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
		"ssh_private_key",
	)
	require.NoError(t, err)

	// Add brokered credentials to target
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

	// Connect to target using ssh option
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", newTargetId, "--",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Successfully connected to target")
}
