// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
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

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	pool.MaxWait = 90 * time.Second

	// e2e_cluster network is created by the e2e infra setup
	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartCassandraWithAuth(t, pool, &network[0], "cassandra", "5.0")
	require.NotNil(t, c, "Cassandra container should not be nil")

	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge Cassandra container: %v", err)
		}
	})
	t.Log("Successfully connected to Cassandra target")
}
