package static_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestConnectTargetCli uses the boundary cli to create a number of supporting objects
// to connect to a target. It then attempts to connect to that target and verifies that
// the connection was successful.
func TestConnectTargetCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	boundary.AuthenticateCli(t)

	// Create an org and project
	newOrgId := boundary.CreateNewOrgCli(t)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)

	// Create a host catalog
	output := e2e.RunCommand("boundary", "host-catalogs", "create", "static",
		"-scope-id", newProjectId,
		"-name", "e2e Automated Test Host Catalog",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "host-catalogs", "delete", "-id", newHostCatalogId)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	output = e2e.RunCommand("boundary", "host-sets", "create", "static",
		"-host-catalog-id", newHostCatalogId,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "host-sets", "delete", "-id", newHostSetId)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host Set: %s", newHostSetId)

	// Create a host
	output = e2e.RunCommand("boundary", "hosts", "create", "static",
		"-host-catalog-id", newHostCatalogId,
		"-name", c.TargetIp,
		"-address", c.TargetIp,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err = json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "hosts", "delete", "-id", newHostId)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Host: %s", newHostId)

	// Add host to host set
	output = e2e.RunCommand("boundary", "host-sets", "add-hosts", "-id", newHostSetId, "-host", newHostId)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a target
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
	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "targets", "delete", "-id", newTargetId)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Logf("Created Target: %s", newTargetId)

	// Add host set to target
	output = e2e.RunCommand("boundary", "targets", "add-host-sources",
		"-id", newTargetId,
		"-host-source", newHostSetId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Connect to target and print host's IP address
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
	require.Equal(t, c.TargetIp, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")
}

// TestCreateTargetApi uses the boundary go api to create a number of supporting objects
// to connect to a target. This test does not connect to the target due to the complexity
// when not using the cli.
func TestCreateTargetApi(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	// Create boundary api client
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	// Create an org and project
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)

	// Create a host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", newProjectId,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
	)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Cleanup(func() {
		_, err := hcClient.Delete(ctx, newHostCatalogId)
		require.NoError(t, err)
	})
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalogId)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Cleanup(func() {
		_, err := hsClient.Delete(ctx, newHostSetId)
		require.NoError(t, err)
	})
	t.Logf("Created Host Set: %s", newHostSetId)

	// Create a host
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, newHostCatalogId,
		hosts.WithName(c.TargetIp),
		hosts.WithStaticHostAddress(c.TargetIp),
	)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Cleanup(func() {
		_, err := hClient.Delete(ctx, newHostId)
		require.NoError(t, err)
	})
	t.Logf("Created Host: %s", newHostId)

	// Add host to host set
	_, err = hsClient.AddHosts(ctx, newHostSetId, 0, []string{newHostId}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)

	// Create a target
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(c.TargetPort, 10, 32)
	require.NoError(t, err)
	newTargetResult, err := tClient.Create(ctx, "tcp", newProjectId,
		targets.WithName("e2e Automated Test Target"),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
	)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Cleanup(func() {
		_, err := tClient.Delete(ctx, newTargetId)
		require.NoError(t, err)
	})
	t.Logf("Created Target: %s", newTargetId)

	// Add host set to target
	_, err = tClient.AddHostSources(ctx, newTargetId, 0,
		[]string{newHostSetId},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}
