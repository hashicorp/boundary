// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliBytesUpDownTransferData uses the cli to verify that the bytes_up/bytes_down fields of a
// session correctly increase when data is transmitting during a session.
func TestCliBytesUpDownTransferData(t *testing.T) {
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
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{target.WithAddress(c.TargetAddress)},
	)
	require.NoError(t, err)

	// Create a session where no additional commands are run
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)

	// Run commands on the target to send data through connection
	go func() {
		t.Log("Starting session...")
		errChan <- e2e.RunCommand(ctxCancel, "boundary",
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
				"for i in {1..30}; do pwd; sleep 1s; done",
			),
		)
	}()
	t.Cleanup(cancel)
	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
	assert.Equal(t, targetId, s.TargetId)

	// Wait until bytes up and down is greater than 0
	t.Log("Waiting for bytes_up/bytes_down to be greater than 0...")
	bytesUp := 0
	bytesDown := 0
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "read", "-id", s.Id, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}
			var newSessionReadResult sessions.SessionReadResult
			err = json.Unmarshal(output.Stdout, &newSessionReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if len(newSessionReadResult.Item.Connections) == 0 {
				return fmt.Errorf("no connections found in session")
			}

			conn := newSessionReadResult.Item.Connections[0]
			bytesUp = int(conn.BytesUp)
			bytesDown = int(conn.BytesDown)

			// Log connection details for debugging rare failures
			t.Logf("Connection - bytes_up: %d, bytes_down: %d, closed_reason: %q, client: %s:%d, endpoint: %s:%d, session status: %s",
				bytesUp, bytesDown, conn.ClosedReason,
				conn.ClientTcpAddress, conn.ClientTcpPort,
				conn.EndpointTcpAddress, conn.EndpointTcpPort,
				newSessionReadResult.Item.Status,
			)

			// Check if the SSH command failed early
			select {
			case result := <-errChan:
				if result.Err != nil {
					return backoff.Permanent(fmt.Errorf("SSH command failed, stdout: %s, stderr: %s", string(result.Stdout), string(result.Stderr)))
				}
				return backoff.Permanent(fmt.Errorf("SSH command completed unexpectedly early, stdout: %s, stderr: %s", string(result.Stdout), string(result.Stderr)))
			default:
				// Command still running, continue checking bytes
			}

			// Check if connection was closed prematurely
			if conn.ClosedReason != "" {
				return backoff.Permanent(fmt.Errorf("connection closed before data transmission: %s", conn.ClosedReason))
			}

			if bytesUp <= 0 || bytesDown <= 0 {
				return fmt.Errorf(
					"bytes_up: %d, bytes_down: %d, bytes_up or bytes_down is not greater than 0",
					bytesUp,
					bytesDown,
				)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	// Confirm that bytes up and down increases
	t.Log("Waiting for bytes_up/bytes_down to increase...")
	var newBytesUp, newBytesDown int
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "read", "-id", s.Id, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}
			var newSessionReadResult sessions.SessionReadResult
			err = json.Unmarshal(output.Stdout, &newSessionReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if len(newSessionReadResult.Item.Connections) == 0 {
				return fmt.Errorf("no connections found in session")
			}

			newBytesUp = int(newSessionReadResult.Item.Connections[0].BytesUp)
			newBytesDown = int(newSessionReadResult.Item.Connections[0].BytesDown)

			if !(newBytesDown > bytesDown) {
				return fmt.Errorf(
					"bytes_up: %d, bytes_down: %d, bytes_up/bytes_down is not greater than previous value",
					newBytesUp,
					newBytesDown,
				)
			}

			t.Logf("bytes_up: %d, bytes_down: %d", newBytesUp, newBytesDown)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 6),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
}
