// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectCassandra uses the boundary cli to connect to a
// target using `connect mysql`
func TestCliTcpTargetConnectCassandra(t *testing.T) {
	e2e.MaybeSkipTest(t)
	ctx := context.Background()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

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

	cassandraYaml, err := os.CreateTemp("", "*")
	require.NoError(t, err, "Failed creating a templ cassandra config yaml file")

	clqlshrc, err := os.CreateTemp("", "*")
	require.NoError(t, err, "Failed creating a templ cassandra config yaml file")

	u, err := url.Parse(c.UriNetwork)
	require.NoError(t, err, "Failed to parse Cassandra URI")

	user := u.User.Username()
	// pw, _ := u.User.Password()
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

	t.Log("Successfully connected to Cassandra target")
}
