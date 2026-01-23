// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

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

// TestCliAlias uses the boundary cli to create an alias and connect to a target
// using that alias
func TestCliAlias(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	// Set up the test
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

	// Create an alias for a target
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{target.WithAddress(c.TargetAddress)},
	)
	require.NoError(t, err)
	aliasTargetAddress := "example.alias.boundary"
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"aliases", "create", "target",
			"-scope-id", "global",
			"-value", aliasTargetAddress,
			"-destination-id", targetId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAliasResult aliases.AliasCreateResult
	err = json.Unmarshal(output.Stdout, &newAliasResult)
	require.NoError(t, err)
	aliasTargetAddressId := newAliasResult.Item.Id
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("aliases", "delete", "-id", aliasTargetAddressId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Connect to target using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", aliasTargetAddress,
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
			"connect", "ssh", aliasTargetAddress, "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Authorize session using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "authorize-session", aliasTargetAddress,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	// Create another alias that uses a target with a host set
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetWithHost, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.TargetPort,
		[]target.Option{target.WithName("targetWithHost")},
	)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetWithHost, hostSetId)
	require.NoError(t, err)
	aliasTargetHost := "aliasTargetHost"
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"aliases", "create", "target",
			"-scope-id", "global",
			"-value", aliasTargetHost,
			"-destination-id", targetWithHost,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	err = json.Unmarshal(output.Stdout, &newAliasResult)
	require.NoError(t, err)
	aliasTargetHostId := newAliasResult.Item.Id
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("aliases", "delete", "-id", aliasTargetHostId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Connect to target with host set using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh", aliasTargetHost, "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create invalid host and add it to the host set
	invalidHostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, "invalid-address")
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, invalidHostId)
	require.NoError(t, err)

	// Update the alias to include the valid host id
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"aliases", "update", "target",
			"-id", aliasTargetHostId,
			"-authorize-session-host-id", hostId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target with host set using alias
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh", aliasTargetHost, "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Use an alias that does not exist. Expect an error
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "ssh", "test.alias", "--",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
}
