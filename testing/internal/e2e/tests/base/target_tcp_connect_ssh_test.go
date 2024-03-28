// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithSsh uses the boundary cli to
// connect to a target using `connect ssh`
func TestCliTcpTargetConnectTargetWithSsh(t *testing.T) {
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
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, newProjectId)
	newCredentialsId := boundary.CreateNewStaticCredentialPrivateKeyCli(t, ctx, newCredentialStoreId, c.TargetSshUser, c.TargetSshKeyPath)
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialsId)

	// Get credentials for target
	output := e2e.RunCommand(ctx, "boundary",
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
	retrievedKey += "\n"
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

	// Connect to target using ssh option with remote command
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
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
	t.Log("Successfully connected to target")
}
