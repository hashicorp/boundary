// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static_with_worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

func TestCliWorker(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
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
	newTargetId := boundary.CreateNewAddressTargetCli(t, ctx, newProjectId, c.TargetPort, c.TargetIp)

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
	require.Equal(t, output.ExitCode, 255)
	require.Contains(t, string(output.Stderr), "timed out")
	t.Logf("Successfully detected connection failure")

	// Set correct worker filter, expect connection success
	var workerTags []string
	err = json.Unmarshal([]byte(c.WorkerTags), &workerTags)
	require.NoError(t, err)
	require.NotEmpty(t, workerTags)

	t.Logf("Setting correct worker filter...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-egress-worker-filter", fmt.Sprintf(`"%s" in "/tags/type"`, workerTags[0]),
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
