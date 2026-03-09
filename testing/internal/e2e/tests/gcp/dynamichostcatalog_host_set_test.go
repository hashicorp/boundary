// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package gcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliCreateGcpDynamicHostCatalogWithHostSet uses the boundary cli to create a host catalog with the GCP
// plugin. The test sets up an GCP dynamic host catalog, creates some host sets, sets up a target to
// one of the host sets, and attempts to connect to the target.
func TestCliCreateGcpDynamicHostCatalogWithHostSet(t *testing.T) {
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
	hostSetId1, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, c.GcpHostSetFilter1, "4")
	require.NoError(t, err)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId1, 1)

	// Set up another host set
	hostSetId2, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, c.GcpHostSetFilter2, "4")
	require.NoError(t, err)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId2, 1)

	// Update host set with a different filter
	t.Log("Updating host set 2 with host set 1's filter...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "update", "plugin",
			"-id", hostSetId2,
			"-attr", fmt.Sprintf("filters=%s", c.GcpHostSetFilter1),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId2, 1)

	// update host set to use preferred endpoints
	t.Log("Updating host set 1 to use preferred endpoint...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "update", "plugin",
			"-id", hostSetId1,
			"-preferred-endpoint", fmt.Sprintf("cidr:%s/32", c.GcpTargetAddress),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Get list of all hosts from host catalog
	t.Logf("Looking for items in the host catalog...")
	var actualHostCatalogCount int
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("hosts", "list", "-host-catalog-id", hostCatalogId, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostCatalogListResult hostcatalogs.HostCatalogListResult
			err := json.Unmarshal(output.Stdout, &hostCatalogListResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			t.Logf("Found %v host(s)", len(hostCatalogListResult.GetItems()))

			actualHostCatalogCount = len(hostCatalogListResult.Items)
			if actualHostCatalogCount == 0 {
				return errors.New("No items are appearing in the host catalog")
			}

			t.Logf("Found %d host(s)", actualHostCatalogCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 1, actualHostCatalogCount, "Numbers of hosts in host catalog did not match expected amount")

	// Create target
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.GcpTargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId1)
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

	// Connect to target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect",
			"-target-id", targetId,
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
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Successfully connected to the target")

	addresses := strings.Fields(string(output.Stdout))
	addressFound := false
	var targetIps []string
	err = json.Unmarshal([]byte(c.GcpHostSetIps), &targetIps)
	require.NoError(t, err)
	for _, address := range addresses {
		for _, targetIp := range targetIps {
			if address == targetIp {
				addressFound = true
				break
			}
		}
	}
	require.True(t, addressFound, "Connected host (%s) is not in expected list (%s)", string(output.Stdout), c.GcpHostSetIps)
}

// TestApiCreateGcpDynamicHostCatalog uses the Go api to create a host catalog with the GCP plugin.
// The test sets up an GCP dynamic host catalog, creates a host set, and sets up a target to the
// host set.
func TestApiCreateGCPDynamicHostCatalog(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)

	// Create a dynamic host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "plugin", projectId,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
		hostcatalogs.WithPluginName("gcp"),
		hostcatalogs.WithAttributes(map[string]any{
			"disable_credential_rotation": true,
			"project_id":                  c.GcpProjectId,
			"client_email":                c.GcpClientEmail,
			"zone":                        c.GcpZone,
		}),
		hostcatalogs.WithSecrets(map[string]any{
			"private_key_id": c.GcpPrivateKeyId,
			"private_key":    c.GcpPrivateKey,
		}),
	)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalogId,
		hostsets.WithAttributes(map[string]any{
			"filters": c.GcpHostSetFilter1,
		}),
		hostsets.WithName("e2e Automated Test Host Set"),
	)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	// Get list of hosts in host set
	// Retry is needed here since it can take a few tries before hosts start appearing
	t.Logf("Looking for items in the host set...")
	var actualHostSetCount int
	err = backoff.RetryNotify(
		func() error {
			hostSetReadResult, err := hsClient.Read(ctx, newHostSetId)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostSetCount = len(hostSetReadResult.Item.HostIds)
			if actualHostSetCount == 0 {
				return errors.New("No items are appearing in the host set")
			}

			t.Logf("Found %d hosts", actualHostSetCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully found items in the host set")
	assert.Equal(t, 1, actualHostSetCount, "Numbers of hosts in host set did not match expected amount")

	// Get list of all hosts from host catalog
	// Retry is needed here since it can take a few tries before hosts start appearing
	t.Logf("Looking for items in the host catalog...")
	var actualHostCatalogCount int
	hClient := hosts.NewClient(client)
	err = backoff.RetryNotify(
		func() error {
			hostListResult, err := hClient.List(ctx, newHostCatalogId)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostCatalogCount = len(hostListResult.Items)
			if actualHostCatalogCount == 0 {
				return errors.New("No items are appearing in the host catalog")
			}

			t.Logf("Found %d hosts", actualHostCatalogCount)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Log("Successfully found items in the host catalog")
	assert.Equal(t, 1, actualHostCatalogCount, "Numbers of hosts in host catalog did not match expected amount")
}
