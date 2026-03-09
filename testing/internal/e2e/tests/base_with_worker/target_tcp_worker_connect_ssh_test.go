// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/workers"
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
		e2e.WithArgs("secrets", "enable", fmt.Sprintf("-path=%s", c.VaultSecretPath), "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credential in vault
	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
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
			fmt.Sprintf("-policy=%s", privateKeyPolicyName),
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

	// Create a credential library
	libraryId, err := boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		storeId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
		"ssh_private_key",
	)
	require.NoError(t, err)

	// Try to set a worker filter on a vault credential-store
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-stores", "update", "vault",
			"-id", storeId,
			"worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress),
		),
	)
	require.Error(t, output.Err)
	require.Equal(t, 1, output.ExitCode)

	// Create a target
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{
			target.WithAddress("openssh-server"),
			target.WithEgressWorkerFilter(fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress)),
		},
	)
	require.NoError(t, err)

	// Add brokered credentials to target
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, libraryId)
	require.NoError(t, err)

	// Connect to target and print host's IP address using retrieved credentials
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", targetId,
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
			"-id", targetId,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagCollocated),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", targetId,
			"-remote-command", "hostname -i",
			"--",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.Error(t, output.Err)
	require.Equal(t, 255, output.ExitCode)
	t.Log("Successfully failed to connect to target with wrong worker filter")

	// Try creating targets with an ingress worker filter. This should result in
	// an error
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "create", "tcp",
			"-name", "Target with Ingress Filter",
			"-scope-id", projectId,
			"-default-port", c.TargetPort,
			"-ingress-worker-filter", `"tag" in "/tags/type"`,
		),
	)
	require.Error(t, output.Err, "Unexpectedly created a target with an ingress worker filter")

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "create", "tcp",
			"-name", "Target with Ingress Filter",
			"-scope-id", projectId,
			"-default-port", c.TargetPort,
			"-ingress-worker-filter", `"tag" in "/tags/type"`,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress),
		),
	)
	require.Error(t, output.Err, "Unexpectedly created a target with an ingress worker filter")

	// Add an API tag and use that tag in the worker filter
	t.Log("Adding API tag to worker...")
	workerList, err := boundary.GetWorkersByTagCli(t, ctx, "type", "egress")
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "add-worker-tags",
			"-id", workerList[0].Id,
			"-tag", "k=v",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		_ = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"workers", "remove-worker-tags",
				"-id", workerList[0].Id,
				"-tag", "k=v",
			),
		)
	})
	// Update target to use new tag
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", targetId,
			"-egress-worker-filter", `"v" in "/tags/k"`,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"connect", "ssh",
					"-target-id", targetId,
					"-remote-command", "hostname -i",
					"--",
					"-o", "UserKnownHostsFile=/dev/null",
					"-o", "StrictHostKeyChecking=no",
					"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				),
			)
			if output.Err != nil {
				return errors.New(string(output.Stderr))
			}

			require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully connected to target with new filter")

	// Update worker to have a different tag. This should result in a failed connection
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "set-worker-tags",
			"-id", workerList[0].Id,
			"-tag", "a=v",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		_ = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"workers", "remove-worker-tags",
				"-id", workerList[0].Id,
				"-tag", "a=v",
			),
		)
	})

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh",
			"-target-id", targetId,
			"-remote-command", "hostname -i",
			"--",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.Error(t, output.Err)
	require.Equal(t, 1, output.ExitCode)
	t.Log("Successfully failed to connect to target with wrong filter")

	// Update target to use new tag
	t.Log("Changing API tag on worker...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", targetId,
			"-egress-worker-filter", `"v" in "/tags/a"`,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"connect", "ssh",
					"-target-id", targetId,
					"-remote-command", "hostname -i",
					"--",
					"-o", "UserKnownHostsFile=/dev/null",
					"-o", "StrictHostKeyChecking=no",
					"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				),
			)
			if output.Err != nil {
				return errors.New(string(output.Stderr))
			}

			require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully connected to target with new filter")

	// Remove API tags
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "remove-worker-tags",
			"-id", workerList[0].Id,
			"-tag", "a=v",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "read",
			"-id", workerList[0].Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var workerReadResult workers.WorkerReadResult
	err = json.Unmarshal(output.Stdout, &workerReadResult)
	require.NoError(t, err)
	require.NotContains(t, workerReadResult.Item.CanonicalTags["k"], "v")
	require.NotContains(t, workerReadResult.Item.CanonicalTags["a"], "v")

	// Add an API tag that's the same as a config tag
	t.Log("Adding API tag that's the same as a config tag...")
	require.NoError(t, err)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "add-worker-tags",
			"-id", workerList[0].Id,
			"-tag", fmt.Sprintf("%s=%s", "type", c.WorkerTagEgress),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		_ = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"workers", "remove-worker-tags",
				"-id", workerList[0].Id,
				"-tag", fmt.Sprintf("%s=%s", "type", c.WorkerTagEgress),
			),
		)
	})
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", targetId,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"connect", "ssh",
					"-target-id", targetId,
					"-remote-command", "hostname -i",
					"--",
					"-o", "UserKnownHostsFile=/dev/null",
					"-o", "StrictHostKeyChecking=no",
					"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				),
			)
			if output.Err != nil {
				return errors.New(string(output.Stderr))
			}

			require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully connected to target")

	// Remove API tag
	t.Log("Removing API tag...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "remove-worker-tags",
			"-id", workerList[0].Id,
			"-tag", fmt.Sprintf("%s=%s", "type", c.WorkerTagEgress),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs(
					"connect", "ssh",
					"-target-id", targetId,
					"-remote-command", "hostname -i",
					"--",
					"-o", "UserKnownHostsFile=/dev/null",
					"-o", "StrictHostKeyChecking=no",
					"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				),
			)
			if output.Err != nil {
				return errors.New(string(output.Stderr))
			}

			require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully connected to target")
}
