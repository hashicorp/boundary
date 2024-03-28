// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliBytesUpDownEmpty uses the cli to verify that the bytes_up/bytes_down fields of a
// session correctly increase when data is transmitting during a session.
func TestCliBytesUpDownEmpty(t *testing.T) {
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
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Create a session where no additional commands are run
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)
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
			),
		)
	}()
	t.Cleanup(cancel)

	session := boundary.WaitForSessionCli(t, ctx, newProjectId)
	assert.Equal(t, newTargetId, session.TargetId)
	assert.Equal(t, newHostId, session.HostId)

	// Confirm that bytesUp and bytesDown do not change
	bytesUp := 0
	bytesDown := 0

	// Wait until bytes up and down is greater than 0
	t.Log("Waiting for bytes_up/bytes_down to be greater than 0...")
	for i := 0; i < 3; i++ {
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("sessions", "read", "-id", session.Id, "-format", "json"),
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

	t.Log("Reading bytes_up/bytes_down values...")
	for i := 0; i < 3; i++ {
		time.Sleep(2 * time.Second)

		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("sessions", "read", "-id", session.Id, "-format", "json"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var newSessionReadResult sessions.SessionReadResult
		err = json.Unmarshal(output.Stdout, &newSessionReadResult)
		require.NoError(t, err)
		bytesUp = int(newSessionReadResult.Item.Connections[0].BytesUp)
		bytesDown = int(newSessionReadResult.Item.Connections[0].BytesDown)

		if i != 1 {
			require.Equal(t, bytesUp, int(newSessionReadResult.Item.Connections[0].BytesUp))
			require.Equal(t, bytesDown, int(newSessionReadResult.Item.Connections[0].BytesDown))
		}

		t.Logf("bytes_up: %d, bytes_down: %d", bytesUp, bytesDown)
	}
}
