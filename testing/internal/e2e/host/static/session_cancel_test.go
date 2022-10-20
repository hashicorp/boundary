package static_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionCancelCli uses the boundary cli to start and then cancel a session
func TestSessionCancelCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	boundary.AuthenticateAdminCli(t)
	newOrgId := boundary.CreateNewOrgCli(t)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, newTargetId, newHostSetId)

	// Connect to target to create a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)
	go func() {
		errChan <- e2e.RunCommand(ctxCancel, "boundary", "connect",
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
		)
	}()
	t.Cleanup(cancel)

	// Get list of sessions
	ctx := context.Background()
	var session *sessions.Session
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary", "sessions", "list", "-scope-id", newProjectId, "-format", "json")
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var sessionListResult sessions.SessionListResult
			err = json.Unmarshal(output.Stdout, &sessionListResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			sessionCount := len(sessionListResult.Items)
			if sessionCount == 0 {
				return errors.New("No items are appearing in the session list")
			}

			t.Logf("Found %d session(s)", sessionCount)
			if sessionCount != 1 {
				return backoff.Permanent(errors.New("Only one session was expected to be found"))
			}

			session = sessionListResult.Items[0]
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	assert.Equal(t, newTargetId, session.TargetId)
	assert.Equal(t, newHostId, session.HostId)
	require.Equal(t, "active", session.Status)

	// Cancel session
	output := e2e.RunCommand(ctx, "boundary", "sessions", "cancel", "-id", session.Id)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary", "sessions", "read", "-id", session.Id, "-format", "json")
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
