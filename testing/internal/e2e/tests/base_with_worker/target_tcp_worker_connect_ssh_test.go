// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_with_worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetWorkerConnectTarget uses the boundary cli to do the
// following...
// - create a target with an egress worker filter and confirm that you can
// connect to it
// - update the target to use a worker filter that can't reach the host and
// confirm that you cannot connect to it
// - attempt to create a target with an ingress worker filter and confirm that
// the operation fails
// Note: This test is specific to the community version
func TestCliTcpTargetWorkerConnectTarget(t *testing.T) {
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
	newTargetId := boundary.CreateNewTargetCli(
		t,
		ctx,
		newProjectId,
		c.TargetPort,
		target.WithAddress("openssh-server"),
		target.WithEgressWorkerFilter(fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress)),
	)

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

	// Add brokered credentials to target
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialLibraryId)

	// Connect to target and print host's IP address using retrieved credentials
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", newTargetId,
			"-remote-command", "hostname -i",
			"--",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	// Note: If this test fails due to: "Unable to connect to worker at
	// worker:9402", modify your /etc/hosts file to contain...
	// `127.0.0.1  localhost  worker``
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
	t.Log("Successfully connected to target")

	// Update the egress filter to one that can't access the target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagCollocated),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", newTargetId,
			"-remote-command", "hostname -i",
			"--",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.Error(t, output.Err)
	require.Equal(t, output.ExitCode, 255)
	t.Log("Successfully failed to connect to target with wrong worker filter")

	// Try creating targets with an ingress worker filter. This should result in
	// an error
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "create", "tcp",
			"-name", "Target with Ingress Filter",
			"-scope-id", newProjectId,
			"-default-port", c.TargetPort,
			"-ingress-worker-filter", `"tag" in "/tags/type"`,
		),
	)
	require.Error(t, output.Err, "Unexpectedly created a target with an ingress worker filter")

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "create", "tcp",
			"-name", "Target with Ingress Filter",
			"-scope-id", newProjectId,
			"-default-port", c.TargetPort,
			"-ingress-worker-filter", `"tag" in "/tags/type"`,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress),
		),
	)
	require.Error(t, output.Err, "Unexpectedly created a target with an ingress worker filter")
}
