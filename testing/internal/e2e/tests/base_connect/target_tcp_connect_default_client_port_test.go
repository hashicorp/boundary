// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetWithTargetClientPort connects to a target with a
// specified default client port and verifies the port is used
func TestCliTcpTargetConnectTargetWithTargetClientPort(t *testing.T) {
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

	var expPort uint32 = 8356

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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, []target.Option{target.WithDefaultClientPort(expPort)})
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Connect to target and print host's IP address
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
			"-exec", "/bin/echo", "--",
			"{{boundary.port}}",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	port := parts[len(parts)-1]

	require.Equal(t, fmt.Sprintf("%d", expPort), port, "specified port was not found")
}
