package static_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionCancelUserCli uses the cli to create a new user and sets up the right permissions for
// the user to connect to the created target. The test also confirms that an admin can cancel the
// user's session.
func TestSessionCancelUserCli(t *testing.T) {
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
	acctName := "e2e-account"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, acctName)
	newUserId := boundary.CreateNewUserCli(t, "global")
	boundary.SetAccountToUserCli(t, newUserId, newAccountId)

	// Try to connect to the target as a user without permissions
	ctx := context.Background()
	boundary.AuthenticateCli(t, acctName, acctPassword)
	output := e2e.RunCommand(ctx, "boundary", "connect",
		"-target-id", newTargetId,
		"-format", "json",
		"-exec", "/usr/bin/ssh", "--",
		"-l", c.TargetSshUser,
		"-i", c.TargetSshKeyPath,
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		"-p", "{{boundary.port}}", // this is provided by boundary
		"{{boundary.ip}}",
		"hostname -i",
	)
	require.Error(t, output.Err, string(output.Stdout), string(output.Stderr))
	var response e2e.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, 403, response.Status)
	t.Log("Successfully received an error when connecting to target as a user without permissions")

	// Create a role
	boundary.AuthenticateAdminCli(t)
	output = e2e.RunCommand(ctx, "boundary", "roles", "create",
		"-scope-id", newProjectId,
		"-name", "e2e Role",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newRoleResult roles.RoleCreateResult
	err = json.Unmarshal(output.Stdout, &newRoleResult)
	require.NoError(t, err)
	newRoleId := newRoleResult.Item.Id
	t.Logf("Created Role: %s", newRoleId)

	// Add grant to role
	output = e2e.RunCommand(ctx, "boundary", "roles", "add-grants",
		"-id", newRoleId,
		"-grant", "id=*;type=target;actions=authorize-session",
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Add user to role
	output = e2e.RunCommand(ctx, "boundary", "roles", "add-principals",
		"-id", newRoleId,
		"-principal", newUserId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target to create a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)
	go func() {
		boundary.AuthenticateCli(t, acctName, acctPassword)
		t.Log("Starting session as user...")
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
	output = e2e.RunCommand(ctx, "boundary", "sessions", "cancel", "-id", session.Id)
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

// TestCreateUserApi uses the go api to create a new user and add some grants to the user
func TestCreateUserApi(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	newHostSetId := boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId)
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetApi(t, ctx, client, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, newHostSetId)

	acctName := "e2e-account"
	newAcctId, _ := boundary.CreateNewAccountApi(t, ctx, client, acctName)
	newUserId := boundary.CreateNewUserApi(t, ctx, client, "global")
	uClient := users.NewClient(client)
	uClient.SetAccounts(ctx, newUserId, 0, []string{newAcctId})

	rClient := roles.NewClient(client)
	newRoleResult, err := rClient.Create(ctx, newProjectId)
	require.NoError(t, err)
	newRoleId := newRoleResult.Item.Id
	t.Logf("Create Role: %s", newRoleId)

	_, err = rClient.AddGrants(ctx, newRoleId, 0, []string{"id=*;type=target;actions=authorize-session"},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	_, err = rClient.AddPrincipals(ctx, newRoleId, 0, []string{newUserId},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
