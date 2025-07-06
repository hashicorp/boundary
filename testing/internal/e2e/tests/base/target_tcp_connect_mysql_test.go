// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
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

	ctx := context.Background()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// e2e_cluster network is created by the e2e infra setup
	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	mysqlContainer := infra.StartMysql(t, pool, &network[0], "mysql", "8.0")
	t.Cleanup(func() {
		pool.Purge(mysqlContainer.Resource)
	})

	// MySQL credentials (these are set in infra.StartMysql)
	mysqlUser, mysqlPassword, mysqlDb, networkAlias, mysqlPort := parseMySQLDSN(mysqlContainer.UriNetwork)

	// Wait for MySQL to be ready
	err = pool.Retry(func() error {
		return exec.CommandContext(ctx, "docker", "exec", mysqlContainer.Resource.Container.ID,
			"mysql", "-u"+mysqlUser, "-p"+mysqlPassword, "-e", "SELECT 1").Run()
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
		mysqlPort,
		target.WithAddress(networkAlias),
	)
	require.NoError(t, err)

	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialPasswordCli(
		t,
		ctx,
		storeId,
		mysqlUser,
		mysqlPassword,
	)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx,
		"boundary",
		"connect", "mysql",
		"-target-id", targetId,
		"-dbname", mysqlDb,
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	// t.Cleanup(func() {
	// 	err := f.Close()
	// 	require.NoError(t, err)
	// })

	_, err = f.Write([]byte("SHOW TABLES;\n")) // list all tables
	require.NoError(t, err)
	_, err = f.Write([]byte("SELECT DATABASE();\n")) // show current database
	require.NoError(t, err)
	_, err = f.Write([]byte("EXIT;\n")) // exit mysql session
	require.NoError(t, err)
	_, err = f.Write([]byte{4}) // EOT (End of Transmission - marks end of file stream)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, f)

	output := buf.String()
	t.Logf("MySQL session output: %s", output)

	require.Contains(t, output, "| "+mysqlDb+" |", "Session did not return expected database query result")
	t.Log("Successfully connected to MySQL target")
}

// Helper function to parse MySQL DSN
func parseMySQLDSN(dsn string) (mysqlUser, mysqlPassword, mysqlDb, networkAlias, mysqlPort string) {
	parts := strings.Split(dsn, "@")
	credsPart := parts[0]
	creds := strings.Split(credsPart, ":")
	mysqlUser = creds[0]
	mysqlPassword = creds[1]

	dbParts := strings.Split(parts[1], "/")
	mysqlDb = dbParts[1]

	hostParts := strings.Split(parts[1], "(")
	hostPort := strings.Split(hostParts[1], ")")[0]
	hostPortFields := strings.Split(hostPort, ":")
	networkAlias = hostPortFields[0]
	mysqlPort = hostPortFields[1]

	return mysqlUser, mysqlPassword, mysqlDb, networkAlias, mysqlPort
}
