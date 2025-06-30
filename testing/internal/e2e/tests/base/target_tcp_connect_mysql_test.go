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
	"github.com/stretchr/testify/require"
	"github.com/ory/dockertest/v3"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
)

// TestCliTcpTargetConnectMysql uses the boundary cli to connect to a
// target using `connect mysql`
func TestCliTcpTargetConnectMysql(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := context.Background()
	
	// Create docker test infrastructure
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	
	network, err := pool.CreateNetwork("e2e-mysql-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.RemoveNetwork(network)
	})

	// Start MySQL container (using official MySQL image)
	mysqlContainer := infra.StartMysql(t, pool, network, "mysql", "8.0")
	t.Cleanup(func() {
		pool.Purge(mysqlContainer.Resource)
	})

	// Wait for MySQL to be ready
	err = pool.Retry(func() error {
		return exec.CommandContext(ctx, "docker", "exec", mysqlContainer.Resource.Container.ID, 
			"mysql", "-ue2eboundary", "-pe2eboundary", "-e", "SELECT 1").Run()
	})
	require.NoError(t, err, "MySQL container failed to start")

	// MySQL credentials (these are set in infra.StartMysql)
	mysqlUser := "e2eboundary"
	mysqlPassword := "e2eboundary" 
	mysqlDbName := "e2eboundarydb"

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
	
	// Use localhost address and extract only port number from Docker's host:port format
	hostPort := mysqlContainer.Resource.GetHostPort("3306/tcp")
	mysqlPort := strings.Split(hostPort, ":")[1] // Extract port from "localhost:55058" format
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		mysqlPort,
		target.WithAddress("localhost"),
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

	var cmd *exec.Cmd
	cmd = exec.CommandContext(ctx,
		"boundary",
		"connect", "mysql",
		"-target-id", targetId,
		"-dbname", mysqlDbName,
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

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
	
	require.Contains(t, output, "| "+mysqlDbName+" |", "Session did not return expected database query result")
	
	require.True(t, 
		strings.Contains(output, "mysql>") || strings.Contains(output, "MySQL ["),
		"Session did not show MySQL/MariaDB prompt")
	t.Log("Successfully connected to MySQL target")
} 
