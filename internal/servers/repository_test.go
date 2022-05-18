package servers_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/recovery"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryNonces(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// Set these low so that we can not have the test run forever
	globals.RecoveryTokenValidityPeriod = 10 * time.Second
	globals.WorkerAuthNonceValidityPeriod = 10 * time.Second
	controller.NonceCleanupInterval = 20 * time.Second

	wrapper := db.TestWrapper(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		RecoveryKms: wrapper,
	})
	defer tc.Shutdown()

	externalWrappers := tc.Kms().GetExternalWrappers(context.Background())
	externalRecovery := externalWrappers.Recovery()
	require.Equal(externalRecovery, wrapper)

	client := tc.Client()
	repo := tc.ServersRepo()

	// First, validate that we can't use the same token twice. Get two tokens,
	// try to use the first twice (should succeed first time, fail second), then
	// ensure second token works
	token1, err := recovery.GenerateRecoveryToken(tc.Context(), wrapper)
	require.NoError(err)
	token2, err := recovery.GenerateRecoveryToken(tc.Context(), wrapper)
	require.NoError(err)

	// Token 1, try 1
	client.SetToken(token1)
	roleClient := roles.NewClient(client)
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	nonces, err := repo.ListNonces(tc.Context(), servers.NoncePurposeRecovery)
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 1, try 2
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.Error(err)
	nonces, err = repo.ListNonces(tc.Context(), servers.NoncePurposeRecovery)
	require.NoError(err)
	assert.Len(nonces, 1)

	// Token 2
	roleClient.ApiClient().SetToken(token2)
	_, err = roleClient.Create(tc.Context(), scope.Global.String())
	require.NoError(err)
	nonces, err = repo.ListNonces(tc.Context(), servers.NoncePurposeRecovery)
	require.NoError(err)
	assert.Len(nonces, 2)

	// Make sure they get cleaned up
	time.Sleep(2 * controller.NonceCleanupInterval)
	nonces, err = repo.ListNonces(tc.Context(), servers.NoncePurposeRecovery)
	require.NoError(err)
	assert.Len(nonces, 0)

	// And finally, make sure they still can't be used
	for _, token := range []string{token1, token2} {
		roleClient.ApiClient().SetToken(token)
		_, err = roleClient.Create(tc.Context(), scope.Global.String())
		require.Error(err)
		nonces, err = repo.ListNonces(tc.Context(), servers.NoncePurposeRecovery)
		require.NoError(err)
		assert.Len(nonces, 0)
	}
}

func TestTagUpdatingListing(t *testing.T) {
	require := require.New(t)

	wrapper := db.TestWrapper(t)
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		RecoveryKms: wrapper,
	})
	defer tc.Shutdown()

	repo := tc.ServersRepo()
	wConf := servers.NewWorkerConfig("test_worker_1",
		servers.WithAddress("127.0.0.1"),
		servers.WithWorkerTags(
			&servers.Tag{
				Key:   "tag1",
				Value: "value1",
			},
			&servers.Tag{
				Key:   "tag1",
				Value: "value2",
			}))

	_, _, err := repo.UpsertWorkerConfig(tc.Context(), wConf, servers.WithUpdateTags(true))
	require.NoError(err)

	wConf = servers.NewWorkerConfig("test_worker_2",
		servers.WithAddress("127.0.0.1"),
		servers.WithWorkerTags(
			&servers.Tag{
				Key:   "tag2",
				Value: "value1",
			},
			&servers.Tag{
				Key:   "tag2",
				Value: "value2",
			}))
	_, _, err = repo.UpsertWorkerConfig(tc.Context(), wConf, servers.WithUpdateTags(true))
	require.NoError(err)

	tags, err := repo.ListTagsForWorkers(tc.Context(), []string{"test_worker_1", "test_worker_2"})
	require.NoError(err)

	// Base case
	exp := map[string][]*servers.Tag{
		"test_worker_1": {
			{
				Key:   "tag1",
				Value: "value1",
			}, {
				Key:   "tag1",
				Value: "value2",
			},
		},
		"test_worker_2": {
			{
				Key:   "tag2",
				Value: "value1",
			},
			{
				Key:   "tag2",
				Value: "value2",
			},
		},
	}
	require.Equal(exp, tags)

	// Update without saying to update tags
	wConf = servers.NewWorkerConfig("test_worker_2",
		servers.WithAddress("192.168.1.1"),
		servers.WithWorkerTags(
			&servers.Tag{
				Key:   "tag22",
				Value: "value21",
			},
			&servers.Tag{
				Key:   "tag22",
				Value: "value22",
			}))
	_, _, err = repo.UpsertWorkerConfig(tc.Context(), wConf)
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(tc.Context(), []string{"test_worker_1", "test_worker_2"})
	require.NoError(err)
	require.Equal(exp, tags)

	// Update tags and test again
	_, _, err = repo.UpsertWorkerConfig(tc.Context(), wConf, servers.WithUpdateTags(true))
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(tc.Context(), []string{"test_worker_1", "test_worker_2"})
	require.NoError(err)
	require.NotEqual(exp, tags)
	// Update and try again
	exp["test_worker_2"] = []*servers.Tag{
		{
			Key:   "tag22",
			Value: "value21",
		},
		{
			Key:   "tag22",
			Value: "value22",
		},
	}
	require.Equal(exp, tags)
}

func TestListServersWithLiveness(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()

	newWorkerConfig := func(publicId string) *servers.WorkerConfig {
		result := servers.NewWorkerConfig(publicId,
			servers.WithAddress("127.0.0.1"))
		_, rowsUpdated, err := serversRepo.UpsertWorkerConfig(ctx, result)
		require.NoError(err)
		require.Equal(1, rowsUpdated)

		return result
	}

	workConf1 := newWorkerConfig("test_worker_1")
	workConf2 := newWorkerConfig("test_worker_2")
	workConf3 := newWorkerConfig("test_worker_3")

	// Sleep the default liveness time (15sec currently) +1s
	time.Sleep(time.Second * 16)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, rowsUpdated, err := serversRepo.UpsertWorkerConfig(ctx, workConf1)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	requireIds := func(expected []string, actual []*servers.Worker) {
		require.Len(expected, len(actual))
		want := make(map[string]struct{})
		for _, v := range expected {
			want[v] = struct{}{}
		}

		got := make(map[string]struct{})
		for _, v := range actual {
			got[v.PublicId] = struct{}{}
		}

		require.Equal(want, got)
	}

	// Default liveness, should only list 1
	result, err := serversRepo.ListWorkers(ctx)
	require.NoError(err)
	require.Len(result, 1)
	requireIds([]string{workConf1.WorkerId}, result)

	// Upsert second server.
	_, rowsUpdated, err = serversRepo.UpsertWorkerConfig(ctx, workConf2)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	// Static liveness. Should get two, so long as this did not take
	// more than 5s to execute.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(time.Second*5))
	require.NoError(err)
	require.Len(result, 2)
	requireIds([]string{workConf1.WorkerId, workConf2.WorkerId}, result)

	// Liveness disabled, should get all three workers.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(-1))
	require.NoError(err)
	require.Len(result, 3)
	requireIds([]string{workConf1.WorkerId, workConf2.WorkerId, workConf3.WorkerId}, result)
}

func TestUpsertWorkerConfig(t *testing.T) {
	// test name colissions between new kms workers and existing workers when new workers are created

	// test no name provided
}
