// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithLocalhost uses the boundary cli to connect
// to a target using `boundary connect` and then `ssh localhost`
func TestCliTcpTargetConnectTargetWithLocalhost(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
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
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, projectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	cmdChan := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
		cmdChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", newTargetId,
				"-listen-port", port,
				"-format", "json",
			),
		)
	}()
	t.Cleanup(cancel)

	boundary.WaitForSessionCli(t, ctx, projectId)

	// Connect to target and print host's IP address
	output := e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"hostname -i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
	require.Equal(t, 0, output.ExitCode)

	// Run a bash command
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"bash -c 'mkdir /tmp/hello && rmdir /tmp/hello'",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, 0, output.ExitCode)

	// Run another bash command
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"bash -c 'echo hello'",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, "hello", strings.TrimSpace(string(output.Stdout)))
	require.Equal(t, 0, output.ExitCode)

	// Run a command with exit code of 1
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"rm test.txt",
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
	require.Equal(t, 1, output.ExitCode) // rm: cannot remove 'test.txt': No such file or directory

	// Cancel session
	cancel()

	// Check output from session
	select {
	case output := <-cmdChan:
		type connectOutput struct {
			Port int
		}
		var response connectOutput
		err = json.Unmarshal(output.Stdout, &response)
		require.NoError(t, err)
		require.Equal(t, port, fmt.Sprint(response.Port))
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}
}
