package servers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestLookupWorkerByWorkerReportedName(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	w := servers.TestWorker(t, conn, wrapper)
	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorkerByWorkerReportedName(ctx, w.GetWorkerReportedName())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w.Worker, got.Worker, protocmp.Transform()))
	})
	t.Run("not found", func(t *testing.T) {
		got, err := repo.LookupWorkerByWorkerReportedName(ctx, "unknown_name")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestLookupWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	w := servers.TestWorker(t, conn, wrapper)
	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorker(ctx, w.GetPublicId())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w.Worker, got.Worker, protocmp.Transform()))
	})
	t.Run("not found", func(t *testing.T) {
		got, err := repo.LookupWorkerByWorkerReportedName(ctx, "w_unknownid")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestUpsertWorkerStatus(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	wStatus1 := servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithAddress("address"), servers.WithName("config_name1"))
	worker, err := repo.UpsertWorkerStatus(ctx, wStatus1)
	require.NoError(t, err)
	{
		assert.True(t, strings.HasPrefix(worker.GetPublicId(), "w_"))
		assert.Equal(t, wStatus1.GetWorkerReportedAddress(), worker.CanonicalAddress())
		assert.Empty(t, worker.Name)
		assert.Equal(t, worker.GetLastStatusTime(), worker.UpdateTime)
		assert.Equal(t, uint32(1), worker.Version)
		assert.Empty(t, worker.Address)
		assert.Empty(t, worker.Description)
	}

	failureCases := []struct {
		name      string
		status    *servers.Worker
		errAssert func(*testing.T, error)
	}{
		{
			name: "no address",
			status: servers.NewWorkerForStatus(scope.Global.String(),
				servers.WithName("worker_with_no_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "cant specifying public id",
			status: func() *servers.Worker {
				w := servers.NewWorkerForStatus(scope.Global.String(),
					servers.WithName("worker_with_no_address"),
					servers.WithAddress("workeraddress"))
				w.PublicId = "w_specified"
				return w
			}(),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "no name",
			status: servers.NewWorkerForStatus(scope.Global.String(),
				servers.WithAddress("no_name_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name:   "no status",
			status: nil,
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "empty scope",
			status: servers.NewWorkerForStatus("",
				servers.WithAddress("address"),
				servers.WithName("config_name1")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
	}
	for _, tc := range failureCases {
		t.Run(fmt.Sprintf("Failures %s", tc.name), func(t *testing.T) {
			_, err = repo.UpsertWorkerStatus(ctx, tc.status)
			assert.Error(t, err)
			tc.errAssert(t, err)

			// Still only the original worker exists.
			workers, err := repo.ListWorkers(ctx)
			require.NoError(t, err)
			assert.Len(t, workers, 1)
		})
	}

	{
		anotherStatus := servers.NewWorkerForStatus(scope.Global.String(),
			servers.WithName("another_test_worker"),
			servers.WithAddress("address"))
		_, err = repo.UpsertWorkerStatus(ctx, anotherStatus)
		require.NoError(t, err)
		{
			workers, err := repo.ListWorkers(ctx)
			require.NoError(t, err)
			assert.Len(t, workers, 2)
		}
	}
}

func TestTagUpdatingListing(t *testing.T) {
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()

	worker1 := servers.TestWorker(t, conn, wrapper)
	wStatus := servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithName(worker1.GetWorkerReportedName()),
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

	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus,
		servers.WithUpdateTags(true))
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value1", "value2"}, worker1.CanonicalTags()["tag1"])

	// Update without saying to update tags
	wStatus = servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithName(worker1.GetWorkerReportedName()),
		servers.WithAddress(worker1.GetWorkerReportedAddress()),
		servers.WithWorkerTags(
			&servers.Tag{
				Key:   "tag22",
				Value: "value21",
			},
			&servers.Tag{
				Key:   "tag22",
				Value: "value22",
			}))
	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus)
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value1", "value2"}, worker1.CanonicalTags()["tag1"])

	// Update tags and test again
	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus, servers.WithUpdateTags(true))
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value21", "value22"}, worker1.CanonicalTags()["tag22"])
}

func TestListWorkersWithLiveness(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()

	worker1 := servers.TestWorker(t, conn, wrapper)
	worker2 := servers.TestWorker(t, conn, wrapper)
	worker3 := servers.TestWorker(t, conn, wrapper)

	// Sleep the default liveness time (15sec currently) +1s
	time.Sleep(time.Second * 16)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, err = serversRepo.UpsertWorkerStatus(ctx, servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithName(worker1.GetWorkerReportedName()),
		servers.WithAddress(worker1.GetWorkerReportedAddress())))
	require.NoError(err)

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
	requireIds([]string{worker1.GetPublicId()}, result)

	// Upsert second server.
	_, err = serversRepo.UpsertWorkerStatus(ctx, servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithName(worker2.GetWorkerReportedName()),
		servers.WithAddress(worker1.GetWorkerReportedAddress())))
	require.NoError(err)

	// Static liveness. Should get two, so long as this did not take
	// more than 5s to execute.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(time.Second*5))
	require.NoError(err)
	require.Len(result, 2)
	requireIds([]string{worker1.GetPublicId(), worker2.GetPublicId()}, result)

	// Liveness disabled, should get all three workers.
	result, err = serversRepo.ListWorkers(ctx, servers.WithLiveness(-1))
	require.NoError(err)
	require.Len(result, 3)
	requireIds([]string{worker1.GetPublicId(), worker2.GetPublicId(), worker3.GetPublicId()}, result)
}
