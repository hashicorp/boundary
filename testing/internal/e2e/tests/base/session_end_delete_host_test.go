// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package base_test

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

// TestCliSessionEndWhenHostIsDeleted tests that an active session is canceled when the respective
// host set for the session is deleted.
func TestCliSessionEndWhenHostIsDeleted(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
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
	newRoleId := boundary.CreateNewRoleCli(t, ctx, newProjectId)
	boundary.AddGrantToRoleCli(t, ctx, newRoleId, "id=*;type=target;actions=authorize-session")
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
	s := boundary.WaitForSessionCli(t, ctx, newProjectId)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
	assert.Equal(t, newTargetId, s.TargetId)
	assert.Equal(t, newHostId, s.HostId)

	// Delete Host
	t.Log("Deleting host...")
	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("hosts", "delete", "-id", newHostId))
	require.NoError(t, output.Err, string(output.Stderr))

	// Check if session has terminated
	select {
	case output := <-errChan:
		// `boundary connect` returns a 255 when cancelled
		require.Equal(t, 255, output.ExitCode, string(output.Stdout), string(output.Stderr))
	case <-time.After(time.Second * 5):
		t.Fatal("Timed out waiting for session command to exit")
	}

	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusTerminated.String())
	t.Log("Session successfully ended after host was deleted")
}
