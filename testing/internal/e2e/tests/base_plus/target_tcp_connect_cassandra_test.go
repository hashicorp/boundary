// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectCassandra uses the boundary cli to connect to a
// target using `connect cassandra`
func TestCliTcpTargetConnectCassandra(t *testing.T) {
	e2e.MaybeSkipTest(t)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// Increase timeout to accommodate Cassandra's longer startup duration due to gossip needing to settle
	pool.MaxWait = 90 * time.Second
	ctx := t.Context()

	// e2e_cluster network is created by the e2e infra setup
	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartCassandra(t, pool, &network[0], "cassandra", "latest")
	require.NotNil(t, c, "Cassandra container should not be nil")
	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge Cassandra container: %v", err)
		}
	})

	u, err := url.Parse(c.UriNetwork)
	t.Log(u)
	require.NoError(t, err, "Failed to parse Cassandra URL")

	user, hostname, port, keyspace := u.User.Username(), u.Hostname(), u.Port(), u.Path[1:]
	pw, pwSet := u.User.Password()

	t.Logf("Cassandra info: user=%s, keyspace=%s, host=%s, port=%s, password-set:%t",
		user, keyspace, hostname, port, pwSet)

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
		"connect", "cassandra",
		"-target-id", targetId,
		"-keyspace", keyspace,
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	_, err = f.Write([]byte("DESCRIBE KEYSPACES;\n"))
	require.NoError(t, err)
	_, err = fmt.Fprintf(f, "SELECT keyspace_name FROM system_schema.keyspaces WHERE keyspace_name = '%s';\n", keyspace)
	require.NoError(t, err)
	_, err = f.Write([]byte("exit\n"))
	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, f)

	output := buf.String()
	t.Logf("Cassandra session output: %s", output)

	require.Contains(t, output, "keyspace_name")
	require.Contains(t, output, keyspace)

	t.Log("Successfully connected to Cassandra target")
}
