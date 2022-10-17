package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewHostCatalogApi creates a new host catalog in boundary using the go api.
// Returns the id of the new host catalog.
func CreateNewHostCatalogApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) string {
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", projectId,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
	)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	return newHostCatalogId
}

// CreateNewHostSetApi creates a new host set in boundary using the go api.
// Returns the id of the new host set.
func CreateNewHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string) string {
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, hostCatalogId)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	return newHostSetId
}

// CreateNewHostApi creates a new host in boundary using the go api
// Returns the id of the new host.
func CreateNewHostApi(t testing.TB, ctx context.Context, client *api.Client, hostCatalogId string, address string) string {
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, hostCatalogId,
		hosts.WithName(address),
		hosts.WithStaticHostAddress(address),
	)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	return newHostId
}

// AddHostToHostSetApi adds a host to a host set using the go api
func AddHostToHostSetApi(t testing.TB, ctx context.Context, client *api.Client, hostSetId string, hostId string) {
	hsClient := hostsets.NewClient(client)
	_, err := hsClient.AddHosts(ctx, hostSetId, 0, []string{hostId}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)
}

// CreateNewHostCatalogCli creates a new host catalog in boundary using the cli.
// Returns the id of the new host catalog.
func CreateNewHostCatalogCli(t testing.TB, projectId string) string {
	output := e2e.RunCommand("boundary", "host-catalogs", "create", "static",
		"-scope-id", projectId,
		"-name", "e2e Automated Test Host Catalog",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err := json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id

	t.Logf("Created Host Catalog: %s", newHostCatalogId)
	return newHostCatalogId
}

// CreateNewHostSetCli creates a new host set in boundary using the cli.
// Returns the id of the new host set.
func CreateNewHostSetCli(t testing.TB, hostCatalogId string) string {
	output := e2e.RunCommand("boundary", "host-sets", "create", "static",
		"-host-catalog-id", hostCatalogId,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err := json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	return newHostSetId
}

// CreateNewHostCli creates a new host in boundary using the cli.
// Returns the id of the new host.
func CreateNewHostCli(t testing.TB, hostCatalogId string, address string) string {
	output := e2e.RunCommand("boundary", "hosts", "create", "static",
		"-host-catalog-id", hostCatalogId,
		"-name", address,
		"-address", address,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err := json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	return newHostId
}

// AddHostToHostSetCli adds a host to a host set using the cli
func AddHostToHostSetCli(t testing.TB, hostSetId string, hostId string) {
	output := e2e.RunCommand("boundary", "host-sets", "add-hosts", "-id", hostSetId, "-host", hostId)
	require.NoError(t, output.Err, string(output.Stderr))
}
