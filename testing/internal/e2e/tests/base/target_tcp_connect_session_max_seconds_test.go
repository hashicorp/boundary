// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

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

// TestCliTcpTargetConnectTargetWithSessionMaxSeconds connects to a target that
// has session max seconds defined. An error should return when trying to
// connect to the target after the time limit has been reached.
func TestCliTcpTargetConnectTargetWithSessionMaxSeconds(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	sessionMaxSeconds := 7
	newTargetId := boundary.CreateNewTargetCli(
		t,
		ctx,
		newProjectId,
		c.TargetPort,
		target.WithAddress(c.TargetAddress),
		target.WithSessionMaxSeconds(uint32(sessionMaxSeconds)),
	)

	// Start a long-running session
	var start time.Time
	ctxCancel, cancel := context.WithCancel(context.Background())
	sessionChannel := make(chan *e2e.CommandResult)
	go func() {
		start = time.Now()
		sessionChannel <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", newTargetId,
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
	s := boundary.WaitForSessionCli(t, ctx, newProjectId)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())

	// Check that session was closed once time limit is reached
	select {
	case output := <-sessionChannel:
		require.Equal(t, 255, output.ExitCode, string(output.Stdout), string(output.Stderr))

		// Ensure that the session did not run for longer than the time limit
		// (plus a small buffer)
		require.Less(t, time.Since(start).Seconds(), float64(sessionMaxSeconds+1))
	case <-time.After(time.Second * time.Duration(sessionMaxSeconds+5)):
		t.Fatal("Timed out waiting for session command to exit")
	}
}
