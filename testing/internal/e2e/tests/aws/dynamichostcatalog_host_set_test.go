// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sessionRegex = regexp.MustCompile("Session ID:\\s+(.+)(?:$|\n)")

// TestCliCreateAwsDynamicHostCatalogWithHostSet uses the boundary cli to create a host catalog with the AWS
// plugin. The test sets up an AWS dynamic host catalog, creates some host sets, sets up a target to
// one of the host sets, and attempts to connect to the target.
func TestCliCreateAwsDynamicHostCatalogWithHostSet(t *testing.T) {
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
	hostSetId1, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, c.AwsHostSetFilter1, c.IpVersion)
	require.NoError(t, err)
	var targetIps1 []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps1), &targetIps1)
	expectedHostSetCount1 := len(targetIps1)
	require.NoError(t, err)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId1, expectedHostSetCount1)

	// Set up another host set
	hostSetId2, err := boundary.CreatePluginHostSetCli(t, ctx, hostCatalogId, c.AwsHostSetFilter2, c.IpVersion)
	require.NoError(t, err)
	var targetIps2 []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps2), &targetIps2)
	require.NoError(t, err)
	expectedHostSetCount2 := len(targetIps2)
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId2, expectedHostSetCount2)

	// Update host set with a different filter
	t.Log("Updating host set 2 with host set 1's filter...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"host-sets", "update", "plugin",
			"-id", hostSetId2,
			"-attr", fmt.Sprintf("filters=%s", c.AwsHostSetFilter1),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	boundary.WaitForNumberOfHostsInHostSetCli(t, ctx, hostSetId2, expectedHostSetCount1)

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
	var targetId string
	if c.IpVersion == "4" {
		targetId, err = boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, nil)
	} else {
		targetId, err = boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort,
			[]target.Option{target.WithIngressWorkerFilter(fmt.Sprintf(`"%s" in "/tags/type"`, c.WorkerTagCollocated))},
		)
	}

	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId1)
	require.NoError(t, err)

	// Create static credentials and add them to the target
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialPrivateKeyCli(t, ctx, storeId, c.TargetSshUser, c.TargetSshKeyPath)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	// Connect to target
	ctxCancel, cancel := context.WithCancel(context.Background())
	go func() {
		e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"ssh",
				"-target-id", targetId,
				"-remote-command", "hostname -i; sleep 60",
				"--",
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "StrictHostKeyChecking=no",
				"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			),
		)
	}()
	t.Cleanup(cancel)

	s := boundary.WaitForSessionCli(t, ctx, projectId, nil)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("sessions", "read", "-id", s.Id, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var sessionReadResult sessions.SessionReadResult
	err = json.Unmarshal(output.Stdout, &sessionReadResult)
	require.NoError(t, err)
	s = sessionReadResult.Item

	require.Greater(t, len(s.Connections), 0)
	var hostIp string
	switch c.IpVersion {
	case "4", "6", "dual":
		hostIp = s.Connections[0].EndpointTcpAddress
	default:
		require.Fail(t, "unknown ip version", c.IpVersion)
	}
	require.Contains(t, targetIps1, hostIp, fmt.Sprintf("Connected host (%s) is not in expected list (%s)", hostIp, targetIps1))
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
		hostcatalogs.WithPluginName("aws"),
		hostcatalogs.WithAttributes(map[string]any{
			"disable_credential_rotation": true,
			"region":                      c.AwsRegion,
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
