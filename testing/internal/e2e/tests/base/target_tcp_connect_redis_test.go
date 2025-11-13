// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"io"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectRedis uses the boundary cli to connect to a target using `connect redis`
func TestCliTcpTargetConnectRedis(t *testing.T) {
	e2e.MaybeSkipTest(t)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	ctx := context.Background()

	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartRedis(t, pool, &network[0], "redis", "latest")
	require.NotNil(t, c, "Redis container should not be nil")
	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge Redis container: %v", err)
		}
	})

	u, err := url.Parse(c.UriNetwork)
	t.Log(u)
	require.NoError(t, err, "Failed to parse Redis URL")

	user, hostname, port := u.User.Username(), u.Hostname(), u.Port()
	pw, pwSet := u.User.Password()

	t.Logf("Redis info: user=%s, host=%s, port=%s, password-set:%t",
		user, hostname, port, pwSet)

	// Wait for Redis to be ready
	err = pool.Retry(func() error {
		out, e := exec.CommandContext(ctx, "docker", "exec", hostname,
			"redis-cli", "-h", hostname, "-p", port, "PING").CombinedOutput()
		t.Logf("Redis PING output: %s", out)
		return e
	})
	require.NoError(t, err, "Redis container failed to start")

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

	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		port,
		[]target.Option{target.WithAddress(hostname)},
	)
	require.NoError(t, err)

	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)

	credentialId, err := boundary.CreateStaticCredentialUsernamePasswordCli(
		t,
		ctx,
		storeId,
		user,
		pw,
	)
	require.NoError(t, err)

	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	t.Logf("Attempting to connect to Redis target %s", targetId)

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

	output, err := sendRedisCommand(stdin, stdout, "SET e2etestkey e2etestvalue\r\n")
	require.NoError(t, err)
	require.Equal(t, "OK", output)

	output, err = sendRedisCommand(stdin, stdout, "GET e2etestkey\r\n")
	require.NoError(t, err)
	require.Equal(t, "e2etestvalue", output)

	output, err = sendRedisCommand(stdin, stdout, "QUIT\r\n")
	require.Equal(t, io.EOF, err)
	require.Empty(t, output)

	// Confirm that boundary connect has closed
	err = cmd.Wait()
	require.NoError(t, err)
}

func sendRedisCommand(stdin io.WriteCloser, stdout io.ReadCloser, cmdStr string) (string, error) {
	_, err := stdin.Write([]byte(cmdStr))
	if err != nil {
		return "", err
	}
	buf := make([]byte, 1024)
	n, err := stdout.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}
