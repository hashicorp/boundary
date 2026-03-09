// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"context"
	"io"
	"os/exec"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectRedisUsernamePassword uses the boundary cli to connect to a target
// using `connect redis` and a username-password credential.
func TestCliTcpTargetConnectRedisUsernamePassword(t *testing.T) {
	e2e.MaybeSkipTest(t)

	// Setup
	ctx := t.Context()
	redisInfo := infra.SetupRedisContainer(t)
	boundary.AuthenticateAdminCli(t, ctx)

	// Create Boundary resources
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

	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		redisInfo.Port,
		[]target.Option{target.WithAddress(redisInfo.Hostname)},
	)
	require.NoError(t, err)

	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialUsernamePasswordCli(
		t,
		ctx,
		storeId,
		redisInfo.Username,
		redisInfo.Password,
	)
	require.NoError(t, err)

	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	// Validate redis connect
	cmd := exec.CommandContext(ctx,
		"boundary",
		"connect", "redis",
		"-target-id", targetId,
	)

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	output, err := infra.SendRedisCommand(stdin, stdout, "ACL WHOAMI\r\n")
	require.NoError(t, err)
	require.Equal(t, redisInfo.Username, output)

	output, err = infra.SendRedisCommand(stdin, stdout, "SET e2etestkey e2etestvalue\r\n")
	require.NoError(t, err)
	require.Equal(t, "OK", output)

	output, err = infra.SendRedisCommand(stdin, stdout, "GET e2etestkey\r\n")
	require.NoError(t, err)
	require.Equal(t, "e2etestvalue", output)

	output, err = infra.SendRedisCommand(stdin, stdout, "QUIT\r\n")
	require.Equal(t, io.EOF, err)
	require.Empty(t, output)

	// Confirm that boundary connect has closed
	err = cmd.Wait()
	require.NoError(t, err)
}
