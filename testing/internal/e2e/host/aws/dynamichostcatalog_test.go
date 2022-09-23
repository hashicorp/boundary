package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type config struct {
	AwsAccessKeyId     string `envconfig:"E2E_AWS_ACCESS_KEY_ID"`
	AwsSecretAccessKey string `envconfig:"E2E_AWS_SECRET_ACCESS_KEY"`
	AwsHostSetFilter1  string `envconfig:"E2E_AWS_HOST_SET_FILTER1"`
	AwsHostSetCount1   string `envconfig:"E2E_AWS_HOST_SET_COUNT1"`
	AwsHostSetIps1     string `envconfig:"E2E_AWS_HOST_SET_IPS1"`
	AwsHostSetFilter2  string `envconfig:"E2E_AWS_HOST_SET_FILTER2"`
	AwsHostSetCount2   string `envconfig:"E2E_AWS_HOST_SET_COUNT2"`
	TargetSshKeyPath   string `envconfig:"E2E_SSH_KEY_PATH"` // e.g. /Users/username/key.pem
	TargetSshUser      string `envconfig:"E2E_SSH_USER"`     // e.g. ubuntu
	TargetPort         string `envconfig:"E2E_SSH_PORT" default:"22"`
}

func (c *config) validate() error {
	if c.AwsAccessKeyId == "" {
		return errors.New("AwsAccessKeyId is empty. Set environment variable: E2E_AWS_ACCESS_KEY_ID")
	}
	if c.AwsSecretAccessKey == "" {
		return errors.New("AwsSecretAccessKey is empty. Set environment variable: E2E_AWS_SECRET_ACCESS_KEY")
	}
	if c.AwsHostSetFilter1 == "" {
		return errors.New("AwsHostSetFilter1 is empty. Set environment variable: E2E_AWS_HOST_SET_FILTER1")
	}
	if c.AwsHostSetCount1 == "" {
		return errors.New("AwsHostSetCount1 is empty. Set environment variable: E2E_AWS_HOST_SET_COUNT1")
	}
	if c.AwsHostSetFilter2 == "" {
		return errors.New("AwsHostSetFilter2 is empty. Set environment variable: E2E_AWS_HOST_SET_FILTER2")
	}
	if c.AwsHostSetCount2 == "" {
		return errors.New("AwsHostSetCount2 is empty. Set environment variable: E2E_AWS_HOST_SET_COUNT2")
	}
	if c.TargetSshKeyPath == "" {
		return errors.New("TargetSshKeyPath is empty. Set environment variable: E2E_SSH_KEY_PATH")
	}
	if c.TargetSshUser == "" {
		return errors.New("TargetSshUser is empty. Set environment variable: E2E_SSH_USER")
	}
	if c.TargetPort == "" {
		return errors.New("TargetPort is empty. Set environment variable: E2E_SSH_PORT")
	}

	return nil
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	err = c.validate()
	if err != nil {
		return nil, err
	}

	return &c, err
}

func TestCreateAwsDynamicHostCatalogCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	boundary.AuthenticateCli(t)

	// Create an org and project
	newOrgId := boundary.CreateNewOrgCli(t)
	t.Logf("Created Org Id: %s", newOrgId)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	t.Logf("Created Project Id: %s", newProjectId)

	// Create a dynamic host catalog
	output := e2e.RunCommand("boundary", "host-catalogs", "create", "plugin",
		"-scope-id", newProjectId,
		"-plugin-name", "aws",
		"-attr", "disable_credential_rotation=true",
		"-attr", "region=us-east-1",
		"-secret", "access_key_id=env://E2E_AWS_ACCESS_KEY_ID",
		"-secret", "secret_access_key=env://E2E_AWS_SECRET_ACCESS_KEY",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set
	output = e2e.RunCommand("boundary", "host-sets", "create", "plugin",
		"-host-catalog-id", newHostCatalogId,
		"-attr", "filters="+c.AwsHostSetFilter1,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSetId1 := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId1)

	// Get list of hosts in host set
	// Retry is needed here since it can take a few tries before hosts start appearing
	t.Logf("Looking for items in the host set...")
	var actualHostSetCount1 int
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand("boundary", "host-sets", "read",
				"-id", newHostSetId1,
				"-format", "json",
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostSetsReadResult hostsets.HostSetReadResult
			err = json.Unmarshal(output.Stdout, &hostSetsReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostSetCount1 = len(hostSetsReadResult.Item.HostIds)
			if actualHostSetCount1 == 0 {
				return errors.New("No items are appearing in the host set")
			}

			t.Logf("Found %d hosts", actualHostSetCount1)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	expectedHostSetCount1, err := strconv.Atoi(c.AwsHostSetCount1)
	require.NoError(t, err)
	assert.Equal(t, expectedHostSetCount1, actualHostSetCount1, "Numbers of hosts in host set did not match expected amount")

	// Create another host set
	output = e2e.RunCommand("boundary", "host-sets", "create", "plugin",
		"-host-catalog-id", newHostCatalogId,
		"-attr", "filters="+c.AwsHostSetFilter2,
		"-name", "e2e Automated Test Host Set2",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult2 hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult2)
	require.NoError(t, err)
	newHostSetId2 := newHostSetResult2.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId2)

	// Get list of hosts in the second host set
	t.Logf("Looking for items in the second host set...")
	var actualHostSetCount2 int
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand("boundary", "host-sets", "read",
				"-id", newHostSetId2,
				"-format", "json",
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostSetsReadResult hostsets.HostSetReadResult
			err = json.Unmarshal(output.Stdout, &hostSetsReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostSetCount2 = len(hostSetsReadResult.Item.HostIds)
			if actualHostSetCount2 == 0 {
				return errors.New("No items are appearing in the host set")
			}

			t.Logf("Found %d hosts", actualHostSetCount2)
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	expectedHostSetCount2, err := strconv.Atoi(c.AwsHostSetCount2)
	require.NoError(t, err)
	assert.Equal(t, expectedHostSetCount2, actualHostSetCount2, "Numbers of hosts in host set did not match expected amount")

	// Get list of all hosts from host catalog
	// Retry is needed here since it can take a few tries before hosts start appearing
	t.Logf("Looking for items in the host catalog...")
	var actualHostCatalogCount int
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand("boundary", "hosts", "list",
				"-host-catalog-id", newHostCatalogId,
				"-format", "json",
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var hostCatalogListResult hostcatalogs.HostCatalogListResult
			err = json.Unmarshal(output.Stdout, &hostCatalogListResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			actualHostCatalogCount = len(hostCatalogListResult.Items)
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
	expectedHostCatalogCount := expectedHostSetCount1 + expectedHostSetCount2
	require.NoError(t, err)
	assert.Equal(t, expectedHostCatalogCount, actualHostCatalogCount, "Numbers of hosts in host catalog did not match expected amount")

	// Create target
	output = e2e.RunCommand("boundary", "targets", "create", "tcp",
		"-scope-id", newProjectId,
		"-default-port", c.TargetPort,
		"-name", "e2e Automated Test Target",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err = json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	// Add host set to target
	output = e2e.RunCommand("boundary", "targets", "add-host-sources",
		"-id", newTargetId,
		"-host-source", newHostSetId1,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target
	output = e2e.RunCommand("boundary", "connect",
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
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	t.Log("Successfully connected to the target")

	// Check if connected host exists in the host set
	var targetIps []string
	err = json.Unmarshal([]byte(c.AwsHostSetIps1), &targetIps)
	hostIpInList := false
	for _, v := range targetIps {
		if v == hostIp {
			hostIpInList = true
		}
	}
	require.True(t, hostIpInList, fmt.Sprintf("Connected host (%s) is not in expected list (%s)", hostIp, targetIps))
}

func TestCreateAwsDynamicHostCatalogApi(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	// Create boundary api client
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	// Create an org and project
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	t.Logf("Created Org Id: %s", newOrgId)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	t.Logf("Created Project Id: %s", newProjectId)

	// Create a dynamic host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "plugin", newProjectId,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
		hostcatalogs.WithPluginName("aws"),
		hostcatalogs.WithAttributes(map[string]interface{}{
			"disable_credential_rotation": true,
			"region":                      "us-east-1",
		}),
		hostcatalogs.WithSecrets(map[string]interface{}{
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
		hostsets.WithAttributes(map[string]interface{}{
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
	expectedHostSetCount, err := strconv.Atoi(c.AwsHostSetCount1)
	require.NoError(t, err)
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
	require.NoError(t, err)
	assert.Equal(t, actualHostCatalogCount, expectedHostSetCount, "Numbers of hosts in host catalog did not match expected amount")
}
