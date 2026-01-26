// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithSessionMaxSecondsTearDown connects to a
// target that has session max seconds defined and executes a long-running
// script. The session should end once the time limit has reached.
func TestCliTcpTargetConnectTargetWithSessionMaxSecondsTearDown(t *testing.T) {
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
	sessionMaxSeconds := 7
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{
			target.WithAddress(c.TargetAddress),
			target.WithSessionMaxSeconds(uint32(sessionMaxSeconds)),
		},
	)
	require.NoError(t, err)

	// Start a long-running session
	var start time.Time
	ctxCancel, cancel := context.WithCancel(context.Background())
	sessionChannel := make(chan *e2e.CommandResult)
	go func() {
		start = time.Now()
		sessionChannel <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", targetId,
				"-exec", "/usr/bin/ssh", "--",
				"-l", c.TargetSshUser,
				"-i", c.TargetSshKeyPath,
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "StrictHostKeyChecking=no",
				"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				"-p", "{{boundary.port}}", // this is provided by boundary
				"{{boundary.ip}}",
				"hostname -i; sleep 60",
			),
		)
	}()
	t.Cleanup(cancel)
	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())

	// Check that session was closed once time limit is reached
	select {
	case output := <-sessionChannel:
		require.Equal(t, 255, output.ExitCode, string(output.Stdout), string(output.Stderr))

		// Ensure that the session did not run for longer than the time limit
		// (plus a small buffer)
		end := time.Since(start).Seconds()
		require.Less(t, end, float64(sessionMaxSeconds+2))
		require.Greater(t, end, float64(sessionMaxSeconds-1))
	case <-time.After(time.Second * time.Duration(sessionMaxSeconds+5)):
		t.Fatal("Timed out waiting for session command to exit")
	}
}

// TestCliTcpTargetConnectTargetWithSessionMaxSecondsRejectNew connects to a
// target that has session max seconds defined. An error should return when
// trying to connect to the target after the time limit has been reached.
func TestCliTcpTargetConnectTargetWithSessionMaxSecondsRejectNew(t *testing.T) {
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
	sessionMaxSeconds := 7
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{
			target.WithAddress(c.TargetAddress),
			target.WithSessionMaxSeconds(uint32(sessionMaxSeconds)),
		},
	)
	require.NoError(t, err)

	// Start a session
	var start time.Time
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	sessionChannel := make(chan *e2e.CommandResult)
	go func() {
		start = time.Now()
		t.Logf("Starting session... %s", start)
		sessionChannel <- e2e.RunCommand(ctxCancel, "boundary",
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

	// Start connections. Expect an error once the time limit is reached
	t.Log("Creating connections...")
	var end time.Time
	for {
		t.Log(time.Now())
		output := e2e.RunCommand(ctx, "ssh",
			e2e.WithArgs(
				"localhost",
				"-p", port,
				"-l", c.TargetSshUser,
				"-i", c.TargetSshKeyPath,
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "StrictHostKeyChecking=no",
				"-o", "IdentitiesOnly=yes", // forces the use of the provided key
				"hostname -i;",
			),
		)

		if output.Err != nil {
			end = time.Now()
			break
		}

		// Ensure that time limit has not been reached yet
		require.Less(t, time.Since(start).Seconds(), float64(sessionMaxSeconds+1))
		time.Sleep(time.Second)
	}

	// Ensure that the session did not run for longer than the time limit
	diff := end.Sub(start).Seconds()
	require.Less(t, diff, float64(sessionMaxSeconds+2))
	require.Greater(t, diff, float64(sessionMaxSeconds-1))
}
