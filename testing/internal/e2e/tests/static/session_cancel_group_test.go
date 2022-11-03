package static_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliSessionCancelGroup uses the cli to create a new user and sets up the right permissions for
// the user to connect to the created target (via a group). The test also confirms that an admin can
// cancel the user's session.
func TestCliSessionCancelGroup(t *testing.T) {
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
	acctName := "e2e-account"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, acctName)
	newUserId := boundary.CreateNewUserCli(t, ctx, "global")
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Try to connect to the target as a user without permissions
	boundary.AuthenticateCli(t, ctx, acctName, acctPassword)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
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
		),
	)
	require.Error(t, output.Err, string(output.Stdout), string(output.Stderr))
	var response e2e.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, 403, int(response.Status))
	t.Log("Successfully received an error when connecting to target as a user without permissions")

	// Create a group
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "create",
			"-scope-id", "global",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newGroupResult groups.GroupCreateResult
	err = json.Unmarshal(output.Stdout, &newGroupResult)
	require.NoError(t, err)
	newGroupId := newGroupResult.Item.Id
	t.Logf("Created Group: %s", newGroupId)

	// Add user to group
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"groups", "add-members",
			"-id", newGroupId,
			"-member", newUserId,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a role for a group
	newRoleId := boundary.CreateNewRoleCli(t, ctx, newProjectId)
	boundary.AddGrantToRoleCli(t, ctx, newRoleId, "id=*;type=target;actions=authorize-session")
	boundary.AddPrincipalToRoleCli(t, ctx, newRoleId, newGroupId)

	// Connect to target to create a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)
	go func() {
		token := boundary.GetAuthenticationTokenCli(t, ctx, acctName, acctPassword)
		t.Log("Starting session as user...")
		errChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-token", "env://E2E_AUTH_TOKEN",
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
			e2e.WithEnv("E2E_AUTH_TOKEN", token),
		)
	}()
	t.Cleanup(cancel)
	session := boundary.WaitForSessionToBeActiveCli(t, ctx, newProjectId)
	assert.Equal(t, newTargetId, session.TargetId)
	assert.Equal(t, newHostId, session.HostId)

	// Cancel session
	t.Log("Canceling session...")
	output = e2e.RunCommand(ctx, "boundary",
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

// TestApiCreateGroup uses the Go api to create a new group and add some grants to the group
func TestApiCreateGroup(t *testing.T) {
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

	gClient := groups.NewClient(client)
	newGroupResult, err := gClient.Create(ctx, "global")
	require.NoError(t, err)
	newGroupId := newGroupResult.Item.Id
	t.Logf("Created Group: %s", newGroupId)

	_, err = gClient.AddMembers(ctx, newGroupId, 0, []string{newUserId}, groups.WithAutomaticVersioning(true))
	require.NoError(t, err)

	rClient := roles.NewClient(client)
	newRoleResult, err := rClient.Create(ctx, newProjectId)
	require.NoError(t, err)
	newRoleId := newRoleResult.Item.Id
	t.Logf("Created Role: %s", newRoleId)

	_, err = rClient.AddGrants(ctx, newRoleId, 0, []string{"id=*;type=target;actions=authorize-session"},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	_, err = rClient.AddPrincipals(ctx, newRoleId, 0, []string{newGroupId},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
