// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

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

	ctx := t.Context()
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
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	cmdChan := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
		cmdChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", targetId,
				"-listen-port", port,
				"-format", "json",
			),
		)
	}()
	t.Cleanup(cancel)

	boundary.WaitForSessionCli(t, ctx, projectId, nil)

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
