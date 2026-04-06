// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectPending uses the boundary cli to connect
// to a target using `boundary connect`, waits for 10 seconds to ensure the session is still active, and then uses ssh to connect through the session
func TestCliTcpTargetConnectPending(t *testing.T) {
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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, []target.Option{target.WithAddress(c.TargetAddress)})
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

	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusPending.String())

	t.Log("Waiting 10 seconds to ensure session is still active...")
	time.Sleep(10 * time.Second)

	select {
	case output := <-cmdChan:
		t.Fatalf("boundary connect exited early: stdout=%s stderr=%s", output.Stdout, output.Stderr)
	default:
	}
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusPending.String())

	output := e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes",
			"hostname -i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
	require.Equal(t, 0, output.ExitCode)

	cancel()

	select {
	case <-cmdChan:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for session command to exit")
	}
}
