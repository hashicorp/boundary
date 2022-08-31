package target_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type config struct {
	TargetIp         string `envconfig:"E2E_TARGET_IP"`    // e.g. 192.168.0.1
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH"` // e.g. /Users/username/key.pem
	TargetSshUser    string `envconfig:"E2E_SSH_USER"`     // e.g. ubuntu
	TargetPort       string `envconfig:"E2E_SSH_PORT" default:"22"`
}

func (c *config) validate() error {
	if c.TargetIp == "" {
		return errors.New("TargetIp is empty. Set environment variable: E2E_TARGET_IP")
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

	return &c, err
}

// TestConnectTargetCli uses the boundary cli to create a number of supporting objects
// to connect to a target. It then attempts to connect to that target and verifies that
// the connection was successful.
func TestConnectTargetCli(t *testing.T) {
	e2e.MaybeSkipTest(t)

	c, err := loadConfig()
	require.NoError(t, err)
	err = c.validate()
	require.NoError(t, err)

	output := boundary.AuthenticateCli()
	require.NoError(t, output.Err, string(output.Stderr))

	// Create an org
	output = e2e.RunCommand(
		"boundary", "scopes", "create",
		"-name", "e2e Automated Test Org",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newOrgResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &newOrgResult)
	require.NoError(t, err)
	newOrg := newOrgResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "scopes", "delete", "-id", newOrg.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Org Id: %s", newOrg.Id)

	// Create a project
	output = e2e.RunCommand(
		"boundary", "scopes", "create",
		"-scope-id", newOrg.Id,
		"-name", "e2e Automated Test Project",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newProjectResult scopes.ScopeCreateResult
	err = json.Unmarshal(output.Stdout, &newProjectResult)
	require.NoError(t, err)
	newProject := newProjectResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "scopes", "delete", "-id", newProject.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Project Id: %s", newProject.Id)

	// Create a host catalog
	output = e2e.RunCommand(
		"boundary", "host-catalogs", "create", "static",
		"-scope-id", newProject.Id,
		"-name", "e2e Automated Test Host Catalog",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalog := newHostCatalogResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "host-catalogs", "delete", "-id", newHostCatalog.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host Catalog: %s", newHostCatalog.Id)

	// Create a host set and add to catalog
	output = e2e.RunCommand(
		"boundary", "host-sets", "create", "static",
		"-host-catalog-id", newHostCatalog.Id,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSet := newHostSetResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "host-sets", "delete", "-id", newHostSet.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host Set: %s", newHostSet.Id)

	// Create a host
	output = e2e.RunCommand(
		"boundary", "hosts", "create", "static",
		"-host-catalog-id", newHostCatalog.Id,
		"-name", c.TargetIp,
		"-address", c.TargetIp,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err = json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHost := newHostResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "hosts", "delete", "-id", newHost.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host: %s", newHost.Id)

	// Add host to host set
	output = e2e.RunCommand(
		"boundary", "host-sets", "add-hosts",
		"-id", newHostSet.Id,
		"-host", newHost.Id,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a target
	output = e2e.RunCommand(
		"boundary", "targets", "create", "tcp",
		"-scope-id", newProject.Id,
		"-default-port", c.TargetPort,
		"-name", "e2e Automated Test Target",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err = json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTarget := newTargetResult.Item
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "targets", "delete", "-id", newTarget.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Target: %s", newTarget.Id)

	// Add host set to target
	output = e2e.RunCommand(
		"boundary", "targets", "add-host-sources",
		"-id", newTarget.Id,
		"-host-source", newHostSet.Id,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address
	output = e2e.RunCommand(
		"boundary", "connect",
		"-target-id", newTarget.Id,
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
	assert.Equal(t, c.TargetIp, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")
}

// TestCreateTargetApi uses the boundary go api to create a number of supporting objects
// to connect to a target. This test does not connect to the target due to the complexity
// when not using the cli.
func TestCreateTargetApi(t *testing.T) {
	e2e.MaybeSkipTest(t)

	c, err := loadConfig()
	require.NoError(t, err)
	err = c.validate()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)

	ctx := context.Background()

	// Create an org
	scopeClient := scopes.NewClient(client)
	newOrgResult, err := scopeClient.Create(ctx, "global", scopes.WithName("e2e Automated Test Org"))
	require.NoError(t, err)
	newOrg := newOrgResult.Item
	t.Cleanup(func() {
		_, err := scopeClient.Delete(ctx, newOrg.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Org Id: %s", newOrg.Id)

	// Create a project
	newProjectResult, err := scopeClient.Create(ctx, newOrg.Id, scopes.WithName("e2e Automated Test Project"))
	require.NoError(t, err)
	newProject := newProjectResult.Item
	t.Cleanup(func() {
		_, err := scopeClient.Delete(ctx, newProject.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Project Id: %s", newProject.Id)

	// Create a host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", newProject.Id,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
	)
	require.NoError(t, err)
	newHostCatalog := newHostCatalogResult.Item
	t.Cleanup(func() {
		_, err := hcClient.Delete(ctx, newHostCatalog.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Host Catalog: %s", newHostCatalog.Id)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalog.Id)
	require.NoError(t, err)
	newHostSet := newHostSetResult.Item
	t.Cleanup(func() {
		_, err := hsClient.Delete(ctx, newHostSet.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Host Set: %s", newHostSet.Id)

	// Create a host
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, newHostCatalog.Id,
		hosts.WithName(c.TargetIp),
		hosts.WithStaticHostAddress(c.TargetIp),
	)
	require.NoError(t, err)
	newHost := newHostResult.Item
	t.Cleanup(func() {
		_, err := hClient.Delete(ctx, newHost.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Host: %s", newHost.Id)

	// Add host to host set
	_, err = hsClient.AddHosts(ctx, newHostSet.Id, 0, []string{newHost.Id}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)

	// Create a target
	tClient := targets.NewClient(client)
	newTargetResult, err := tClient.Create(ctx, "tcp", newProject.Id,
		targets.WithName("e2e Automated Test Target"),
		targets.WithTcpTargetDefaultPort(22),
	)
	require.NoError(t, err)
	newTarget := newTargetResult.Item
	t.Cleanup(func() {
		_, err := tClient.Delete(ctx, newTarget.Id)
		require.NoError(t, err)
	})
	t.Logf("Created Target: %s", newTarget.Id)

	// Add host set to target
	_, err = tClient.AddHostSources(ctx, newTarget.Id, 0,
		[]string{newHostSet.Id},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
