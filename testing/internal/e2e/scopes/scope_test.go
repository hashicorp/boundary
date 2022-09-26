package scope_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListKeyVersionDestructionJobsCli uses the boundary CLI to list
// pending key version destruction jobs.
func TestListKeyVersionDestructionJobsCli(t *testing.T) {
	e2e.MaybeSkipTest(t)

	output := boundary.AuthenticateCli()
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(
		"boundary", "scopes", "list-key-version-destruction-jobs",
		"-scope-id", "global",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var keyVersionDestructionJobListResult scopes.KeyVersionDestructionJobListResult
	err := json.Unmarshal(output.Stdout, &keyVersionDestructionJobListResult)
	require.NoError(t, err)
	assert.Empty(t, keyVersionDestructionJobListResult.Items)
}

// TestListKeyVersionDestructionJobsApi uses the boundary go api to list
// pending key version destruction jobs.
func TestListKeyVersionDestructionJobsApi(t *testing.T) {
	e2e.MaybeSkipTest(t)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)

	ctx := context.Background()

	scopeClient := scopes.NewClient(client)
	keyVersionDestructionJobListResult, err := scopeClient.ListKeyVersionDestructionJobs(ctx, "global")
	require.NoError(t, err)
	assert.Empty(t, keyVersionDestructionJobListResult.Items)
}
