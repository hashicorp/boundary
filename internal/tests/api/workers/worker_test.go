package workers_test

import (
	"testing"

	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerTagsASD(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	tw := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    tc.Config().WorkerAuthKms,
		InitialUpstreams: tc.ClusterAddrs()})
	defer tw.Shutdown()

	workerClient := workers.NewClient(client)

	wcr, err := workerClient.CreateWorkerLed(tc.Context(), tc.Token().Token, scope.Global.String())
	require.NoError(err)

	wcr, err = workerClient.AddWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version,
		map[string][]string{"key": {"value"}})
	require.NoError(err)
	require.NotNil(wcr)
	assert.ElementsMatch(wcr.Item.ApiTags, map[string][]string{"key": {"value"}})

	wcr, err = workerClient.SetWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version,
		map[string][]string{"key2": {"value2", "value3"}})
	require.NoError(err)
	require.NotNil(wcr)
	assert.ElementsMatch(wcr.Item.ApiTags, map[string][]string{"key2": {"value2", "value3"}})

	wcr, err = workerClient.RemoveWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version,
		map[string][]string{"key2": {"value3"}})
	require.NoError(err)
	require.NotNil(wcr)
	assert.ElementsMatch(wcr.Item.ApiTags, map[string][]string{"key2": {"value2"}})

	wcr, err = workerClient.SetWorkerTags(tc.Context(), wcr.Item.Id, wcr.Item.Version, nil)
	require.NoError(err)
	require.NotNil(wcr)
	assert.Empty(wcr.Item.ApiTags)
}
