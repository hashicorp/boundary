package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewOrgApi creates a new organization in boundary using the go api.
// Returns the id of the new org.
func CreateNewOrgApi(t testing.TB, ctx context.Context, client *api.Client) string {
	scopeClient := scopes.NewClient(client)
	newOrgResult, err := scopeClient.Create(ctx, "global", scopes.WithName("e2e Automated Test Org"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := scopeClient.Delete(ctx, newOrgResult.Item.Id)
		require.NoError(t, err)
	})

	return newOrgResult.Item.Id
}

// CreateNewProjectApi creates a new project in boundary using the go api. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateNewProjectApi(t testing.TB, ctx context.Context, client *api.Client, orgId string) string {
	scopeClient := scopes.NewClient(client)
	newProjResult, err := scopeClient.Create(ctx, orgId, scopes.WithName("e2e Automated Test Project"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := scopeClient.Delete(ctx, newProjResult.Item.Id)
		require.NoError(t, err)
	})

	return newProjResult.Item.Id
}

// CreateNewOrgCli creates a new organization in boundary using the cli.
// Returns the id of the new org.
func CreateNewOrgCli(t testing.TB) string {
	output := e2e.RunCommand("boundary", "scopes", "create",
		"-name", "e2e Automated Test Org",
		"-scope-id", "global",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newOrgResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newOrgResult)
	require.NoError(t, err)

	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "scopes", "delete", "-id", newOrgResult.Item.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	return newOrgResult.Item.Id
}

// CreateNewProjectCli creates a new project in boundary using the cli. The project will be created
// under the provided org id.
// Returns the id of the new project.
func CreateNewProjectCli(t testing.TB, orgId string) string {
	output := e2e.RunCommand("boundary", "scopes", "create",
		"-name", "e2e Automated Test Project",
		"-scope-id", orgId,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newProjResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newProjResult)
	require.NoError(t, err)

	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", "scopes", "delete", "-id", newProjResult.Item.Id)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	return newProjResult.Item.Id
}
