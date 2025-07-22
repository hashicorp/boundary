// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"testing"
	"time"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectCassandra uses the boundary cli to connect to a
// target using `connect cassandra`
func TestCliTcpTargetConnectCassandra(t *testing.T) {
	e2e.MaybeSkipTest(t)
	ctx := context.Background()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	pool.MaxWait = 90 * time.Second

	// e2e_cluster network is created by the e2e infra setup
	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartCassandra(t, pool, &network[0], "cassandra", "5.0")
	require.NotNil(t, c, "Cassandra container should not be nil")

	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge Cassandra container: %v", err)
		}
	})

	u, err := url.Parse(c.UriNetwork)
	require.NoError(t, err, "Failed to parse Cassandra URI")

	user := u.User.Username()
	pw, _ := u.User.Password()
	keyspace := u.Path[1:]
	port := u.Port()
	hostname := u.Hostname()

	t.Logf("Cassandra container info: user=%s, keyspace=%s, host=%s, port=%s",
		user, keyspace, hostname, port)

	err = pool.Retry(func() error {
		return exec.CommandContext(ctx, "docker", "exec", hostname,
			"cqlsh", "-e", "SELECT now() FROM system.local;").Run()
	})

	require.NoError(t, err, "Cassandra container failed to start")

	t.Logf("Enabling Password Auth for Cassandra")
	commands := []string{
		"sed", "-i",
		"-e", "s/^authenticator:.*/authenticator: PasswordAuthenticator/",
		"-e", "s/^authorizer:.*/authorizer: CassandraAuthorizer/",
		"-e", "s/^role_manager:.*/role_manager: CassandraRoleManager/",
		"/etc/cassandra/cassandra.yaml",
	}

	_, err = c.Resource.Exec(commands, dockertest.ExecOptions{})
	require.NoError(t, err)

	t.Logf("Restarting Cassandra Container")
	err = pool.Client.RestartContainer(c.Resource.Container.ID, uint(pool.MaxWait.Seconds()))
	require.NoError(t, err)

	err = pool.Retry(func() error {
		return exec.CommandContext(ctx, "docker", "exec", hostname,
			"cqlsh", "-u cassandra", "-p cassandra", "-e", "SELECT now() FROM system.local;").Run()
	})

	require.NoError(t, err, "Cassandra container failed after restart")

	cqlCommands := []string{
		fmt.Sprintf("CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};", keyspace),
		fmt.Sprintf("CREATE ROLE IF NOT EXISTS %s WITH PASSWORD = '%s' AND LOGIN = true;", user, pw),
		fmt.Sprintf("GRANT ALL PERMISSIONS ON KEYSPACE %s TO %s;", keyspace, user),
		fmt.Sprintf("USE %s; CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, name TEXT, created_at TIMESTAMP);", keyspace),
	}

	for _, cqlCmd := range cqlCommands {
		cmd := exec.CommandContext(ctx, "docker", "exec", hostname,
			"cqlsh", "-u", "cassandra", "-p", "cassandra", "-e", cqlCmd)

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Command failed: %s", cqlCmd)
			t.Logf("Error: %s", err.Error())
			t.Logf("Output: %s", string(output))
		}
		require.NoError(t, err, fmt.Sprintf("Failed to execute CQL: %s\nError: %s\nOutput: %s",
			cqlCmd, err.Error(), string(output)))
	}
	t.Log("Successfully connected to Cassandra target")
}
