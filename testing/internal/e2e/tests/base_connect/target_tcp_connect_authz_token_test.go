// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithAuthzToken uses the boundary cli to connect to a target using the
// `authz_token` option
func TestCliTcpTargetConnectTargetWithAuthzToken(t *testing.T) {
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
	name, err := base62.Random(16)
	require.NoError(t, err)
	testProjectName := fmt.Sprintf("e2e Project %s", name)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "create",
			"-scope-id", orgId,
			"-description", "e2e",
			"-name", testProjectName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var createProjResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &createProjResult)
	require.NoError(t, err)
	projectId := createProjResult.Item.Id
	t.Logf("Created Project Id: %s", projectId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	testTargetName := `E2E/Test-Target-With\Name`
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, []target.Option{target.WithName(testTargetName)})
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialPrivateKeyCli(t, ctx, storeId, c.TargetSshUser, c.TargetSshKeyPath)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", targetId, "-format", "json"),
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

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")

	// Authorize session with target name and scope id
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session",
			"-name", testTargetName,
			"-scope-id", projectId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Authorize session with target name and scope name
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session",
			"-name", testTargetName,
			"-scope-name", testProjectName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
