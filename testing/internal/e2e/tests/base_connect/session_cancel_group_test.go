// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/session"
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
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
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
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)
	acctName := "e2e-account"
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, acctName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)

	// Try to connect to the target as a user without permissions
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
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
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, int(response.Status))
	t.Log("Successfully received an error when connecting to target as a user without permissions")

	// Create a group
	boundary.AuthenticateAdminCli(t, ctx)
	groupId, err := boundary.CreateGroupCli(t, ctx, "global")
	require.NoError(t, err)
	err = boundary.AddUserToGroup(t, ctx, userId, groupId)
	require.NoError(t, err)

	// Create a role for a group
	roleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	err = boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=target;actions=authorize-session")
	require.NoError(t, err)
	err = boundary.AddPrincipalToRoleCli(t, ctx, roleId, groupId)
	require.NoError(t, err)

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
				"-target-id", targetId,
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
	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
	assert.Equal(t, targetId, s.TargetId)
	assert.Equal(t, hostId, s.HostId)

	// Cancel session
	t.Log("Canceling session...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("sessions", "cancel", "-id", s.Id),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusTerminated.String())

	// Check output from session
	select {
	case output := <-errChan:
		// `boundary connect` returns a 255 when cancelled
		require.Equal(t, 255, output.ExitCode, string(output.Stdout), string(output.Stderr))
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}

	t.Log("Successfully cancelled session")
}

// TestApiCreateGroup uses the Go api to create a new group and add some grants to the group
func TestApiCreateGroup(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()

	targetPort, err := strconv.ParseUint(c.TargetPort, 10, 32)
	require.NoError(t, err)

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogApi(t, ctx, client, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetApi(t, ctx, client, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostApi(t, ctx, client, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetApi(t, ctx, client, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetApi(t, ctx, client, projectId, "tcp", targets.WithTcpTargetDefaultPort(uint32(targetPort)))
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetApi(t, ctx, client, targetId, hostSetId)
	require.NoError(t, err)

	acctName := "e2e-account"
	accountId, _, err := boundary.CreateAccountApi(t, ctx, client, bc.AuthMethodId, acctName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		aClient := accounts.NewClient(client)
		_, err := aClient.Delete(ctx, accountId)
		require.NoError(t, err)
	})
	userId, err := boundary.CreateUserApi(t, ctx, client, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		uClient := users.NewClient(client)
		_, err := uClient.Delete(ctx, userId)
		require.NoError(t, err)
	})
	uClient := users.NewClient(client)
	_, err = uClient.SetAccounts(ctx, userId, 0, []string{accountId}, users.WithAutomaticVersioning(true))
	require.NoError(t, err)

	gClient := groups.NewClient(client)
	newGroupResult, err := gClient.Create(ctx, "global")
	require.NoError(t, err)
	newGroupId := newGroupResult.Item.Id
	t.Logf("Created Group: %s", newGroupId)

	_, err = gClient.AddMembers(ctx, newGroupId, 0, []string{userId}, groups.WithAutomaticVersioning(true))
	require.NoError(t, err)

	rClient := roles.NewClient(client)
	newRoleResult, err := rClient.Create(ctx, projectId)
	require.NoError(t, err)
	newRoleId := newRoleResult.Item.Id
	t.Logf("Created Role: %s", newRoleId)

	_, err = rClient.AddGrants(ctx, newRoleId, 0, []string{"ids=*;type=target;actions=authorize-session"},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	_, err = rClient.AddPrincipals(ctx, newRoleId, 0, []string{newGroupId},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
