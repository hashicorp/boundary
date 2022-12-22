package static_test

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

// TestCliBytesUpDownTransferData uses the cli to verify that the bytes_up/bytes_down fields of a
// session correctly increase when data is transmitting during a session.
func TestCliBytesUpDownTransferData(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
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
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

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

	session := boundary.WaitForSessionToBeActiveCli(t, ctx, newProjectId)
	assert.Equal(t, newTargetId, session.TargetId)
	assert.Equal(t, newHostId, session.HostId)

	// Confirm that bytesDown is increasing
	bytesUp := 0
	bytesDown := 0
	t.Log("Reading bytes_up/bytes_down values...")
	for i := 0; i < 3; i++ {
		if i != 0 {
			time.Sleep(2 * time.Second)
		}

		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("sessions", "read", "-id", session.Id, "-format", "json"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var newSessionReadResult sessions.SessionReadResult
		err = json.Unmarshal(output.Stdout, &newSessionReadResult)
		require.NoError(t, err)
		require.GreaterOrEqual(t, int(newSessionReadResult.Item.Connections[0].BytesUp), bytesUp)
		bytesUp = int(newSessionReadResult.Item.Connections[0].BytesUp)
		require.Greater(t, int(newSessionReadResult.Item.Connections[0].BytesDown), bytesDown)
		bytesDown = int(newSessionReadResult.Item.Connections[0].BytesDown)

		t.Logf("bytes_up: %d, bytes_down: %d", bytesUp, bytesDown)
	}
}
