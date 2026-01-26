// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliSessionEndWhenTargetIsDeleted tests that an active session is canceled when the respective
// target for the session is deleted.
func TestCliSessionEndWhenTargetIsDeleted(t *testing.T) {
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
	roleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	err = boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=target;actions=authorize-session")
	require.NoError(t, err)
	err = boundary.AddPrincipalToRoleCli(t, ctx, roleId, userId)
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

	// Delete Target
	t.Log("Deleting target...")
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("targets", "delete", "-id", targetId))
	require.NoError(t, output.Err, string(output.Stderr))

	// Check if session has terminated
	t.Log("Waiting for session to be canceling/terminated...")
	select {
	case output := <-errChan:
		// `boundary connect` returns a 255 when cancelled
		require.Equal(t, 255, output.ExitCode, string(output.Stdout), string(output.Stderr))
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}

	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusTerminated.String())
	t.Log("Session successfully ended after target was deleted")
}
