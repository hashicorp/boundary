// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"net/url"
	"os/exec"
	"testing"

	"github.com/creack/pty"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectRedis uses the boundary cli to connect to a target using `connect redis`
func TestCliTcpTargetConnectRedis(t *testing.T) {
	t.Skip("Skipped. Test fails due to issues between redis-cli and pty. Will looked at in future.")
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
		target.WithAddress(hostname),
	)
	require.NoError(t, err)

	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)

	credentialId, err := boundary.CreateStaticCredentialPasswordCli(
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

	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	_, err = f.Write([]byte("SET e2etestkey e2etestvalue\r\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte("GET e2etestkey\r\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte("QUIT\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte{4})
	require.NoError(t, err)

	// commented out below to make manual testing less tedious.
	// io.Copy will hang because not all bytes seem to be written to pty (QUIT is not recognized).

	// var buf bytes.Buffer
	// _, _ = io.Copy(&buf, f)
	// output := buf.String()
	// t.Logf("Redis session output: %s", output)

	// require.Contains(t, output, "OK")
	// require.Contains(t, output, "\"e2etestvalue\"")

	// t.Log("Successfully connected to Redis target")
}
