// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// TestCliCreateAwsDynamicHostCatalogWithHostSet uses the boundary cli to create a host catalog with the AWS
// plugin. The test sets up an AWS dynamic host catalog, creates some host sets, sets up a target to
// one of the host sets, and attempts to connect to the target.
func TestCliCreateAwsDynamicHostCatalogWithHostSet(t *testing.T) {
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
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateAwsHostCatalogCli(t, ctx, projectId, c.AwsAccessKeyId, c.AwsSecretAccessKey)
	require.NoError(t, err)

	// Set up a host set
	newHostSetId1 := boundary.CreateNewAwsHostSetCli(t, ctx, hostCatalogId, c.AwsHostSetFilter1)
	var targetIps1 []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps1), &targetIps1)
	expectedHostSetCount1 := len(targetIps1)
	require.NoError(t, err)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, newHostSetId1, expectedHostSetCount1)

	// Set up another host set
	newHostSetId2 := boundary.CreateNewAwsHostSetCli(t, ctx, hostCatalogId, c.AwsHostSetFilter2)
	var targetIps2 []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps2), &targetIps2)
	require.NoError(t, err)
	expectedHostSetCount2 := len(targetIps2)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, newHostSetId2, expectedHostSetCount2)

	// Update host set with a different filter
	t.Log("Updating host set 2 with host set 1's filter...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "update", "plugin",
			"-id", newHostSetId2,
			"-attr", fmt.Sprintf("filters=%s", c.AwsHostSetFilter1),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, newHostSetId2, expectedHostSetCount1)

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
	expectedHostCatalogCount := expectedHostSetCount1 + expectedHostSetCount2
	assert.Equal(t, expectedHostCatalogCount, actualHostCatalogCount, "Numbers of hosts in host catalog did not match expected amount")

	// Create target
	newTargetId := boundary.CreateNewTargetCli(t, ctx, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId1)

	// Connect to target
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

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	t.Log("Successfully connected to the target")

	// Check if connected host exists in the host set
	hostIpInList := false
	for _, v := range targetIps1 {
		if v == hostIp {
			hostIpInList = true
		}
	}
	require.True(t, hostIpInList, fmt.Sprintf("Connected host (%s) is not in expected list (%s)", hostIp, targetIps1))
}

// TestApiCreateAwsDynamicHostCatalog uses the Go api to create a host catalog with the AWS plugin.
// The test sets up an AWS dynamic host catalog, creates a host set, and sets up a target to the
// host set.
func TestApiCreateAwsDynamicHostCatalog(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
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
		hostcatalogs.WithPluginName("aws"),
		hostcatalogs.WithAttributes(map[string]any{
			"disable_credential_rotation": true,
			"region":                      "us-east-1",
		}),
		hostcatalogs.WithSecrets(map[string]any{
			"access_key_id":     c.AwsAccessKeyId,
			"secret_access_key": c.AwsSecretAccessKey,
		}),
	)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalogId,
		hostsets.WithAttributes(map[string]any{
			"filters": c.AwsHostSetFilter1,
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
	var targetIps []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps1), &targetIps)
	require.NoError(t, err)
	expectedHostSetCount := len(targetIps)
	assert.Equal(t, expectedHostSetCount, actualHostSetCount, "Numbers of hosts in host set did not match expected amount")

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
	assert.Equal(t, actualHostCatalogCount, expectedHostSetCount, "Numbers of hosts in host catalog did not match expected amount")
}
