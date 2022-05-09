package servers_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/servers/store"

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
	srv := &store.Worker{
		PrivateId: "test1",
		Address:   "127.0.0.1",
		Tags: map[string]*store.TagValues{
			"tag1": {
				Values: []string{"value1", "value2"},
			},
		},
	}

	_, _, err := repo.UpsertWorker(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)

	srv = &store.Worker{
		PrivateId: "test2",
		Address:   "127.0.0.1",
		Tags: map[string]*store.TagValues{
			"tag2": {
				Values: []string{"value1", "value2"},
			},
		},
	}
	_, _, err = repo.UpsertWorker(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)

	tags, err := repo.ListTagsForWorkers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)

	// Base case
	exp := []*servers.WorkerTag{
		{
			WorkerId: "test1",
			Key:      "tag1",
			Value:    "value1",
		},
		{
			WorkerId: "test1",
			Key:      "tag1",
			Value:    "value2",
		},
		{
			WorkerId: "test2",
			Key:      "tag2",
			Value:    "value1",
		},
		{
			WorkerId: "test2",
			Key:      "tag2",
			Value:    "value2",
		},
	}
	require.Equal(exp, tags)

	// Update without saying to update tags
	srv = &store.Worker{
		PrivateId: "test2",
		Address:   "192.168.1.1",
		Tags: map[string]*store.TagValues{
			"tag22": {
				Values: []string{"value21", "value22"},
			},
		},
	}
	_, _, err = repo.UpsertWorker(tc.Context(), srv)
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)
	require.Equal(exp, tags)

	// Update tags and test again
	_, _, err = repo.UpsertWorker(tc.Context(), srv, servers.WithUpdateTags(true))
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(tc.Context(), []string{"test1", "test2"})
	require.NoError(err)
	require.NotEqual(exp, tags)
	// Update and try again
	exp[2] = &servers.WorkerTag{
		WorkerId: "test2",
		Key:      "tag22",
		Value:    "value21",
	}
	exp[3] = &servers.WorkerTag{
		WorkerId: "test2",
		Key:      "tag22",
		Value:    "value22",
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

	newWorker := func(privateId string) *store.Worker {
		result := &store.Worker{
			PrivateId: privateId,
			Address:   "127.0.0.1",
		}
		_, rowsUpdated, err := serversRepo.UpsertWorker(ctx, result)
		require.NoError(err)
		require.Equal(1, rowsUpdated)

		return result
	}

	server1 := newWorker("test1")
	server2 := newWorker("test2")
	server3 := newWorker("test3")

	// Sleep the default liveness time (15sec currently) +1s
	time.Sleep(time.Second * 16)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, rowsUpdated, err := serversRepo.UpsertWorker(ctx, server1)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	requireIds := func(expected []string, actual []*store.Worker) {
		require.Len(expected, len(actual))
		want := make(map[string]struct{})
		for _, v := range expected {
			want[v] = struct{}{}
		}

		got := make(map[string]struct{})
		for _, v := range actual {
			got[v.PrivateId] = struct{}{}
		}

		require.Equal(want, got)
	}

	// Default liveness, should only list 1
	result, err := serversRepo.ListWorkers(ctx)
	require.NoError(err)
	require.Len(result, 1)
	requireIds([]string{server1.PrivateId}, result)

	// Upsert second server.
	_, rowsUpdated, err = serversRepo.UpsertWorker(ctx, server2)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	// Static liveness. Should get two, so long as this did not take
	// more than 5s to execute.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(time.Second*5))
	require.NoError(err)
	require.Len(result, 2)
	requireIds([]string{server1.PrivateId, server2.PrivateId}, result)

	// Liveness disabled, should get all three workers.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(-1))
	require.NoError(err)
	require.Len(result, 3)
	requireIds([]string{server1.PrivateId, server2.PrivateId, server3.PrivateId}, result)
}
