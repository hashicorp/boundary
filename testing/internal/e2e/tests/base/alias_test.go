// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliAlias uses the boundary cli to create an alias
func TestCliAlias(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	// Set up the test
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
	newTargetId := boundary.CreateNewTargetCli(
		t,
		ctx,
		newProjectId,
		c.TargetPort,
		target.WithAddress(c.TargetAddress),
	)

	// Create an alias
	alias := "example.alias.boundary"
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"aliases", "create", "target",
			"-scope-id", "global",
			"-value", alias,
			"-destination-id", newTargetId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAliasResult aliases.AliasCreateResult
	err = json.Unmarshal(output.Stdout, &newAliasResult)
	require.NoError(t, err)
	newAliasId := newAliasResult.Item.Id

	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("aliases", "delete", "-id", newAliasId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Connect to target using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", alias,
			"-exec", "/usr/bin/ssh", "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")

	// Connect Ssh to target using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh", alias, "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Successfully connected to target")

	// Authorize session using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session", alias,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	// Add an authorize-session-host-id to the alias
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"aliases", "update", "target",
			"-id", newAliasId,
			"-authorize-session-host-id", newHostId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session", alias,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Use an alias that does not exist. Expect an error
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session", "test.alias",
			"-format", "json",
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
}
