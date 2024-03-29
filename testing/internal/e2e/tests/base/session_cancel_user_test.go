// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliSessionCancelUser uses the cli to create a new user and sets up the right permissions for
// the user to connect to the created target. The test also confirms that an admin can cancel the
// user's session.
func TestCliSessionCancelUser(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
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
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, hostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)
	acctName := "e2e-account"
	newAccountId, acctPassword := boundary.CreateNewAccountCli(t, ctx, bc.AuthMethodId, acctName)
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", newAccountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newUserId := boundary.CreateNewUserCli(t, ctx, "global")
	t.Cleanup(func() {
		boundary.AuthenticateAdminCli(t, context.Background())
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", newUserId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Try to connect to the target as a user without permissions
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
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
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, int(response.Status))
	t.Log("Successfully received an error when connecting to target as a user without permissions")

	// Create a role for user
	boundary.AuthenticateAdminCli(t, ctx)
	newRoleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	boundary.AddGrantToRoleCli(t, ctx, newRoleId, "ids=*;type=target;actions=authorize-session")
	boundary.AddPrincipalToRoleCli(t, ctx, newRoleId, newUserId)

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
	s := boundary.WaitForSessionCli(t, ctx, projectId)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
	assert.Equal(t, newTargetId, s.TargetId)
	assert.Equal(t, newHostId, s.HostId)

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

// TestApiCreateUser uses the Go api to create a new user and add some grants to the user
func TestApiCreateUser(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
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
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, hostSetId)

	acctName := "e2e-account"
	newAcctId, _ := boundary.CreateNewAccountApi(t, ctx, client, bc.AuthMethodId, acctName)
	t.Cleanup(func() {
		aClient := accounts.NewClient(client)
		_, err := aClient.Delete(ctx, newAcctId)
		require.NoError(t, err)
	})
	newUserId := boundary.CreateNewUserApi(t, ctx, client, "global")
	t.Cleanup(func() {
		uClient := users.NewClient(client)
		_, err := uClient.Delete(ctx, newUserId)
		require.NoError(t, err)
	})
	uClient := users.NewClient(client)
	_, err = uClient.SetAccounts(ctx, newUserId, 0, []string{newAcctId}, users.WithAutomaticVersioning(true))
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

	_, err = rClient.AddPrincipals(ctx, newRoleId, 0, []string{newUserId},
		roles.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
