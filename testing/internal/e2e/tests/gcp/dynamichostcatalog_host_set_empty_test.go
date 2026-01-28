// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package gcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliCreateGcpDynamicHostCatalogWithEmptyHostSet uses the boundary cli to create a host catalog with the GCP
// plugin. The test sets up an GCP dynamic host catalog, creates some host sets, sets up a target to
// one of the host sets, and attempts to connect to the target.
func TestCliCreateGcpDynamicHostCatalogWithEmptyHostSet(t *testing.T) {
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
	hostCatalogId, err := boundary.CreateGcpHostCatalogCli(t, ctx, projectId, c.GcpProjectId, c.GcpClientEmail, c.GcpPrivateKeyId, c.GcpPrivateKey, c.GcpZone)
	require.NoError(t, err)

	// Set up a host set
	hostSetId, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, "labels.empty_test=true", "4")
	require.NoError(t, err)

	// Check that there are no hosts in the host set
	t.Logf("Looking for items in the host set...")
	var actualHostSetCount int
	for i := 0; i < 3; i++ {
		if i != 0 {
			time.Sleep(3 * time.Second)
		}

		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"host-sets", "read",
				"-id", hostSetId,
				"-format", "json",
			),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var hostSetsReadResult hostsets.HostSetReadResult
		err := json.Unmarshal(output.Stdout, &hostSetsReadResult)
		require.NoError(t, err)

		actualHostSetCount = len(hostSetsReadResult.Item.HostIds)
		require.Equal(t, 0, actualHostSetCount,
			fmt.Sprintf("Detected incorrect number of hosts. Expected: 0, Actual: %d", actualHostSetCount),
		)
	}
	t.Log("Successfully detected zero hosts in the host set")

	// Check that there are no hosts in the host catalog
	t.Logf("Looking for items in the host catalog...")
	var actualHostCatalogCount int
	for i := 0; i < 3; i++ {
		if i != 0 {
			time.Sleep(3 * time.Second)
		}

		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("hosts", "list", "-host-catalog-id", hostCatalogId, "-format", "json"),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		var hostCatalogListResult hostcatalogs.HostCatalogListResult
		err := json.Unmarshal(output.Stdout, &hostCatalogListResult)
		require.NoError(t, err)

		actualHostCatalogCount = len(hostCatalogListResult.Items)
		require.Equal(t, 0, actualHostCatalogCount,
			fmt.Sprintf("Detected incorrect number of hosts. Expected: 0, Actual: %d", actualHostCatalogCount),
		)
	}
	t.Log("Successfully detected zero hosts in the host catalog")

	// Create target
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.GcpTargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Create a temporary file to store the SSH key string
	tempFile, err := os.CreateTemp("./", "ssh-key.pem")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write the SSH key string to the temporary file
	_, err = tempFile.WriteString(c.GcpTargetSshKey)
	require.NoError(t, err)
	err = tempFile.Close()
	require.NoError(t, err)

	// Attempt to connect to target
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
			"-format", "json",
			"-exec", "/usr/bin/ssh", "--",
			"-l", c.GcpTargetSshUser,
			"-i", tempFile.Name(),
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"-p", "{{boundary.port}}", // this is provided by boundary
			"{{boundary.ip}}",
			"hostname", "-i",
		),
	)
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, response.Status, "Expected to error when connecting to a target with zero hosts")
	t.Log("Successfully failed to connect to target")
}
