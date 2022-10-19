package static_test

import (
	"context"
	"strings"
	"testing"

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
	newOrgId := boundary.CreateNewOrgCli(t)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, newTargetId, newHostSetId)

	// Connect to target and print host's IP address
	ctx := context.Background()
	output := e2e.RunCommand(ctx, "boundary", "connect",
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

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	newHostSetId := boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId)
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetApi(t, ctx, client, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, newHostSetId)
}
