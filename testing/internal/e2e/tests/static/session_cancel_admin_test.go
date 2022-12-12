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

// TestCliSessionCancelAdmin uses the boundary cli to start and then cancel a session
func TestCliSessionCancelAdmin(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Connect to target to create a session
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
				"hostname -i; sleep 60",
			),
		)
	}()
	t.Cleanup(cancel)
	session := boundary.WaitForSessionToBeActiveCli(t, ctx, newProjectId)
	assert.Equal(t, newTargetId, session.TargetId)
	assert.Equal(t, newHostId, session.HostId)

	// Cancel session
	t.Log("Canceling session...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("sessions", "cancel", "-id", session.Id),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("sessions", "read", "-id", session.Id, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionReadResult sessions.SessionReadResult
	err = json.Unmarshal(output.Stdout, &newSessionReadResult)
	require.NoError(t, err)
	require.Condition(t, func() bool {
		return newSessionReadResult.Item.Status == "canceling" || newSessionReadResult.Item.Status == "terminated"
	})

	// Check output from session
	select {
	case output := <-errChan:
		// `boundary connect` returns a 255 when cancelled
		require.Equal(t, output.ExitCode, 255, string(output.Stdout), string(output.Stderr))
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}

	t.Log("Successfully cancelled session")
}
