// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliCreateUpdateTargetAddress asserts that creating and updating a target
// using a valid address is successful.
func TestCliCreateUpdateTargetAddress(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort, target.WithAddress(c.TargetAddress))

	// Connect to target and print host's IP address
	output := e2e.RunCommand(ctx, "boundary",
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
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")

	// Remove target address. We have now no address or host sources.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-address", "null",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address - should error because
	// there's no place to connect to.
	output = e2e.RunCommand(ctx, "boundary",
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
			"hostname", "-i",
		),
	)
	require.Error(t, output.Err, string(output.Stderr))

	var response boundary.CliError
	require.NoError(t, json.Unmarshal(output.Stderr, &response))
	require.Equal(t, http.StatusNotFound, response.Status, "Expected error when connecting to target with no host sources or address")

	// Add a valid address back in.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-address", c.TargetAddress,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address.
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
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts = strings.Fields(string(output.Stdout))
	hostIp = parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")
}

// TestCliTargetAddressToHostSource asserts that we can change a target using an
// address to a target using host sources only if we remove the address first.
// TestCliTargetAddressToHostSource and TestCliTargetHostSourceToAddress are separate,
// independent tests because switching between host sources and address is not a
// commutative operation (they use different codepaths).
func TestCliTargetAddressToHostSource(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort, target.WithAddress(c.TargetAddress))

	// Connect to target and print host's IP address
	output := e2e.RunCommand(ctx, "boundary",
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
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")

	// Attempt add-host-sources. Should error because the target has an address.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "add-host-sources",
			"-id", newTargetId,
			"-host-source", newHostSetId,
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Target add-host-sources did not return expected error")

	var response boundary.CliError
	require.NoError(t, json.Unmarshal(output.Stderr, &response))
	require.Equal(t, http.StatusBadRequest, response.Status, "Expected error when adding host source to target with an address")

	// Attempt set-host-sources. Should error because the target has an address.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "set-host-sources",
			"-id", newTargetId,
			"-host-source", newHostSetId,
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Target set-host-sources did not return expected error")
	require.NoError(t, json.Unmarshal(output.Stderr, &response))
	require.Equal(t, http.StatusBadRequest, response.Status, "Expected error when setting host source to target with an address")

	// Remove the target's address. We should now be able to add/set host
	// sources.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-address", "null",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)
	boundary.SetHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Connect to target and print host's IP address, now using the host source.
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
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts = strings.Fields(string(output.Stdout))
	hostIp = parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")
}

// TestCliTargetHostSourceToAddress asserts that we can change a target using host
// source(s) to a target using an address only if we remove the host sources
// first.
// TestCliTargetAddressToHostSource and TestCliTargetHostSourceToAddress are separate,
// independent tests because switching between host sources and address is not a
// commutative operation (they use different codepaths).
func TestCliTargetHostSourceToAddress(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
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
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, c.TargetAddress)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Connect to target and print host's IP address
	output := e2e.RunCommand(ctx, "boundary",
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
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetAddress, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")

	// Attempt to add an address to the target - should error because we have
	// host sources set.
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-address", c.TargetAddress,
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Target update did not return expected error")

	var response boundary.CliError
	require.NoError(t, json.Unmarshal(output.Stderr, &response))
	require.Equal(t, http.StatusBadRequest, response.Status, "Expected error when setting address to target with a host source")

	boundary.RemoveHostSourceFromTargetCli(t, ctx, newTargetId, newHostSetId)

	// Attempt to add an address to the target again - should work
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "update", "tcp",
			"-id", newTargetId,
			"-address", c.TargetAddress,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address
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
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
