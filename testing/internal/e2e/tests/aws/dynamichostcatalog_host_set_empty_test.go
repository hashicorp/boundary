// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliCreateAwsDynamicHostCatalogWithEmptyHostSet uses the boundary cli to create a host catalog with the AWS
// plugin. The test sets up an AWS dynamic host catalog, creates some host sets, sets up a target to
// one of the host sets, and attempts to connect to the target.
func TestCliCreateAwsDynamicHostCatalogWithEmptyHostSet(t *testing.T) {
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
	hostCatalogId, err := boundary.CreateAwsHostCatalogCli(t, ctx, projectId, c.AwsAccessKeyId, c.AwsSecretAccessKey, c.AwsRegion, c.IpVersion != "4")
	require.NoError(t, err)

	// Set up a host set
	hostSetId, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, "tag:empty_test=true", c.IpVersion)
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
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Attempt to connect to target
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
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
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, response.Status, "Expected to error when connecting to a target with zero hosts")
	t.Log("Successfully failed to connect to target")
}
