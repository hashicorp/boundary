// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"bytes"
	"context"
	"io"
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

// TestCliTcpTargetConnectMysql uses the boundary cli to connect to a
// target using `connect mysql`
func TestCliTcpTargetConnectMysql(t *testing.T) {
	e2e.MaybeSkipTest(t)
	ctx := t.Context()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// e2e_cluster network is created by the e2e infra setup
	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartMysql(t, pool, &network[0], "mysql", "8.0")
	require.NotNil(t, c, "MySQL container should not be nil")
	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge MySQL container: %v", err)
		}
	})

	u, err := url.Parse(c.UriNetwork)
	require.NoError(t, err, "Failed to parse MySQL URL")

	user, hostname, port, db := u.User.Username(), u.Hostname(), u.Port(), u.Path[1:]
	pw, pwSet := u.User.Password()
	t.Logf("MySQL info: user=%s, db=%s, host=%s, port=%s, password-set:%t",
		user, db, hostname, port, pwSet)

	// Wait for MySQL to be ready
	err = pool.Retry(func() error {
		return exec.CommandContext(ctx, "docker", "exec", hostname,
			"mysql", "-u"+user, "-p"+pw, "-e", "SELECT 1").Run()
	})
	require.NoError(t, err, "MySQL container failed to start")

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

	cmd := exec.CommandContext(ctx,
		"boundary",
		"connect", "mysql",
		"-target-id", targetId,
		"-dbname", db,
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	_, err = f.Write([]byte("SHOW TABLES;\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte("SELECT DATABASE();\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte("EXIT;\n"))
	require.NoError(t, err)
	_, err = f.Write([]byte{4})
	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, f)

	output := buf.String()
	t.Logf("MySQL session output: %s", output)

	require.Contains(t, output, "| "+db+" |", "Session did not return expected database query result")
	t.Log("Successfully connected to MySQL target")
}
