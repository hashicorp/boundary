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

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithConnectionLimits connects to a target that
// has connection limits defined. An error should return when the connection
// limit is exhausted
func TestCliTcpTargetConnectTargetWithConnectionLimits(t *testing.T) {
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
	sessionConnectionLimit := 2
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{
			target.WithAddress(c.TargetAddress),
			target.WithSessionConnectionLimit(int32(sessionConnectionLimit)),
		},
	)
	require.NoError(t, err)

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	sessionChannel := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
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

	// Start connections. Expect an error once the limit is reached
	for i := 0; i <= sessionConnectionLimit; i++ {
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

		if i == sessionConnectionLimit {
			require.Error(t, output.Err, string(output.Stderr))
			require.Equal(t, 255, output.ExitCode)
		} else {
			require.NoError(t, output.Err, string(output.Stderr))
			require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output.Stdout)))
			require.Equal(t, 0, output.ExitCode)
		}
	}

	// Check output from session. Session should be automatically terminated due
	// to connection limit being reached
	select {
	case output := <-sessionChannel:
		t.Log(string(output.Stdout))

		// output includes multiple json objects, separated by newlines
		parts := strings.Split(strings.TrimSpace(string(output.Stdout)), "\n")
		require.Greater(t, len(parts), 1, "Expected multiple json objects in output")

		// validate the first json object
		type connectOutput struct {
			Port int
		}
		var cOut connectOutput
		err = json.Unmarshal([]byte(parts[0]), &cOut)
		require.NoError(t, err)
		require.Equal(t, port, fmt.Sprint(cOut.Port))

		// validate the last json object
		type sessionOutput struct {
			TerminationReason string `json:"termination_reason"`
		}
		var sOut sessionOutput
		err = json.Unmarshal([]byte(parts[len(parts)-1]), &sOut)
		require.NoError(t, err)
		require.Contains(t, sOut.TerminationReason, "No connections left in session")
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}
}
