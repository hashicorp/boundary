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

// CreateNewOrgCli creates a new organization in boundary using the cli.
// Returns the id of the new org.
func CreateNewOrgCli(t testing.TB) string {
	return createNewScopeCli(t, "e2e Automated Test Org", "global")
}

// CreateNewProjectCli creates a new project in boundary using the cli.
// Returns the id of the new project.
func CreateNewProjectCli(t testing.TB, scopeId string) string {
	return createNewScopeCli(t, "e2e Automated Test Project", scopeId)
}

func createNewScopeCli(t testing.TB, name string, scopeId string) string {
	output := e2e.RunCommand("boundary", e2e.WithArgs("scopes", "create",
		"-name", name,
		"-scope-id", scopeId,
		"-format", "json",
	))
	require.NoError(t, output.Err, string(output.Stderr))

	var newOrgResult scopes.ScopeCreateResult
	err := json.Unmarshal(output.Stdout, &newOrgResult)
	require.NoError(t, err)

	t.Cleanup(func() {
		output := e2e.RunCommand("boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgResult.Item.Id))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	return newOrgResult.Item.Id
}
