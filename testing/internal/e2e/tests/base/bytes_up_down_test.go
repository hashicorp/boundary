// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/session"
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
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, hostSetId)

	// Create a session where no additional commands are run
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)

	// Run commands on the target to send data through connection
	go func() {
		t.Log("Starting session...")
		errChan <- e2e.RunCommand(ctxCancel, "boundary",
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
				"for i in {1..10}; do pwd; sleep 1s; done",
			),
		)
	}()
	t.Cleanup(cancel)
	s := boundary.WaitForSessionCli(t, ctx, projectId)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
	assert.Equal(t, newTargetId, s.TargetId)
	assert.Equal(t, hostId, s.HostId)

	bytesUp := 0
	bytesDown := 0

	// Wait until bytes up and down is greater than 0
	t.Log("Waiting for bytes_up/bytes_down to be greater than 0...")
	for i := 0; i < 3; i++ {
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("sessions", "read", "-id", s.Id, "-format", "json"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var newSessionReadResult sessions.SessionReadResult
		err = json.Unmarshal(output.Stdout, &newSessionReadResult)
		require.NoError(t, err)

		if len(newSessionReadResult.Item.Connections) > 0 {
			bytesUp = int(newSessionReadResult.Item.Connections[0].BytesUp)
			bytesDown = int(newSessionReadResult.Item.Connections[0].BytesDown)
			t.Logf("bytes_up: %d, bytes_down: %d", bytesUp, bytesDown)

			if bytesUp > 0 && bytesDown > 0 {
				break
			}
		} else {
			t.Log("No connections found in session. Retrying...")
		}

		time.Sleep(2 * time.Second)
	}
	require.Greater(t, bytesUp, 0)
	require.Greater(t, bytesDown, 0)

	// Confirm that bytes up and down increases
	t.Log("Waiting for bytes_up/bytes_down to increase...")
	var newBytesUp, newBytesDown int
	for i := 0; i < 3; i++ {
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("sessions", "read", "-id", s.Id, "-format", "json"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var newSessionReadResult sessions.SessionReadResult
		err = json.Unmarshal(output.Stdout, &newSessionReadResult)
		require.NoError(t, err)
		newBytesUp = int(newSessionReadResult.Item.Connections[0].BytesUp)
		newBytesDown = int(newSessionReadResult.Item.Connections[0].BytesDown)
		t.Logf("bytes_up: %d, bytes_down: %d", newBytesUp, newBytesDown)

		if newBytesDown > bytesDown {
			break
		}

		time.Sleep(2 * time.Second)
	}
	require.GreaterOrEqual(t, newBytesUp, bytesUp)
	require.Greater(t, newBytesDown, bytesDown)
}
