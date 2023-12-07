// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateSessions asserts that the CLI automatically paginates to retrieve
// all sessions in a single invocation.
func TestCliPaginateSessions(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Connect to targets to create a session
	// Create enough sessions to overflow a single page
	ctxCancel, cancel := context.WithCancel(context.Background())
	errChan := make(chan *e2e.CommandResult)
	for i := 0; i < c.MaxPageSize+1; i++ {
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

		s := boundary.WaitForSessionCli(t, ctx, newProjectId)
		boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())
		assert.Equal(t, newTargetId, s.TargetId)
		assert.Equal(t, newHostId, s.HostId)
	}

	t.Cleanup(cancel)

	// List sessions recursively
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialSessions sessions.SessionListResult
	err = json.Unmarshal(output.Stdout, &initialSessions)
	require.NoError(t, err)

	require.Len(t, initialSessions.Items, c.MaxPageSize+1)
	// Note that none of these are returned to the CLI for now.
	assert.Empty(t, initialSessions.ResponseType)
	assert.Empty(t, initialSessions.RemovedIds)
	assert.Empty(t, initialSessions.ListToken)

	// Create a new session and destroy one of the other targets
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

	newSession := boundary.WaitForSessionCli(t, ctx, newProjectId)
	boundary.WaitForSessionStatusCli(t, ctx, newSession.Id, session.StatusActive.String())
	assert.Equal(t, newTargetId, newSession.TargetId)
	assert.Equal(t, newHostId, newSession.HostId)

	// Cancel session
	t.Log("Canceling session...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "cancel",
			"-id", initialSessions.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new target but not the deleted target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "list",
			"-scope-id", newProjectId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	boundary.WaitForSessionStatusCli(t, ctx, initialSessions.Items[0].Id, session.StatusTerminated.String())

	var newSessions sessions.SessionListResult
	err = json.Unmarshal(output.Stdout, &newSessions)
	require.NoError(t, err)

	require.Len(t, newSessions.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new session
	firstItem := newSessions.Items[0]
	assert.Equal(t, newSession.Id, firstItem.Id)
	assert.Empty(t, newSessions.ResponseType)
	assert.Empty(t, newSessions.RemovedIds)
	assert.Empty(t, newSessions.ListToken)
	// Ensure the deleted session isn't returned
	for _, session := range newSessions.Items {
		assert.NotEqual(t, session.Id, initialSessions.Items[0].Id)
	}
}
