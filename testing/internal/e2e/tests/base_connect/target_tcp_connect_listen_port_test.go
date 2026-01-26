// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
)

// TestCliTcpTargetConnectListenPort uses the boundary cli to create a target and
// connect to it multiple times on the same listen port. The cli should return an error when
// a port is already in use.
func TestCliTcpTargetConnectListenPort(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort,
		[]target.Option{target.WithAddress(c.TargetAddress)},
	)
	require.NoError(t, err)

	// Connect to target with client port 3333
	const ListenPort = "3333"

	ctxCancel, cancel := context.WithCancel(ctx)
	sessionChannel := make(chan *e2e.CommandResult)

	go func() {
		sessionChannel <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", targetId,
				"-listen-port", ListenPort,
			),
		)
	}()
	t.Cleanup(cancel)

	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusPending.String())
	t.Logf("Successfully connected to target with listen port %s", ListenPort)

	t.Logf("Starting new connection to target with same listen port %s", ListenPort)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
			"-listen-port", ListenPort,
		),
	)

	require.Error(t, output.Err, "Expected error when connecting to target with same listen port")
	require.Contains(t, string(output.Stderr), "address already in use")
	require.Equal(t, 2, output.ExitCode)
}

// TestCliTcpTargetConnectDefaultClientPort uses the boundary cli to create a target and
// connect to it multiple times on the same client port. The test is similar to the one above,
// but sets DefaultClientPort instead of ListenPort
func TestCliTcpTargetConnectDefaultClientPort(t *testing.T) {
	const DefaultClientPort = 3333
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort,
		[]target.Option{
			target.WithAddress(c.TargetAddress),
			target.WithDefaultClientPort(DefaultClientPort),
		},
	)
	require.NoError(t, err)

	// Connect to target with DefaultClientPort set
	ctxCancel, cancel := context.WithCancel(ctx)
	sessionChannel := make(chan *e2e.CommandResult)

	go func() {
		sessionChannel <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", targetId,
			),
		)
	}()
	t.Cleanup(cancel)

	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusPending.String())
	t.Logf("Successfully connected to target with client port %d", DefaultClientPort)

	t.Logf("Starting new connection to target on client port %d", DefaultClientPort)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
		),
	)

	require.Error(t, output.Err, "Expected error when connecting to target with same listen port")
	require.Contains(t, string(output.Stderr), "address already in use")
	require.Equal(t, 2, output.ExitCode)
}
