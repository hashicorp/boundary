// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aws_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliWorker(t *testing.T) {
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
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort, target.WithAddress(c.TargetAddress))

	// Set incorrect worker filter, expect connection failure
	t.Logf("Setting incorrect worker filter...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-egress-worker-filter", `"prod" in "/tags/type"`,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", newTargetId,
			"-exec", "/usr/bin/ssh", "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"-o", "ConnectTimeout=3",
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
	assert.Equal(t, 255, output.ExitCode)
	require.Contains(t, string(output.Stderr), "timed out")
	t.Logf("Successfully detected connection failure")

	// Set correct worker filter, expect connection success
	t.Logf("Setting correct worker filter...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagEgress),
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", newTargetId,
			"-exec", "/usr/bin/ssh", "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"-o", "ConnectTimeout=3",
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Logf("Successfully connected to target")
}
