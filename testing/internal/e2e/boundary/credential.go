package boundary

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewCredentialStoreStaticApi creates a new static credential store using the Go api.
// Returns the id of the new credential store
func CreateNewCredentialStoreStaticApi(t testing.TB, ctx context.Context, client *api.Client, projectId string) string {
	csClient := credentialstores.NewClient(client)
	newCredentialStoreResult, err := csClient.Create(ctx, "static", projectId, credentialstores.WithName("e2e Credential Store"))
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	return newCredentialStoreId
}

// CreateNewCredentialStoreStaticCli creates a new static credential store using the cli.
// Returns the id of the new credential store
func CreateNewCredentialStoreStaticCli(t testing.TB, projectId string) string {
	output := e2e.RunCommand(context.Background(), "boundary",
		e2e.WithArgs(
			"credential-stores", "create", "static",
			"-scope-id", projectId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err := json.Unmarshal(output.Stdout, &newCredentialStoreResult)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	return newCredentialStoreId
}
