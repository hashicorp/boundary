package servers_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertWorkerStatus(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	wStatus1 := servers.NewWorkerStatus("test_worker_1",
		servers.WithAddress("address"),
		servers.WithName("config_name1"))
	_, _, err = repo.UpsertWorkerStatus(ctx, wStatus1)
	require.NoError(t, err)
	{
		workers, err := repo.ListWorkers(ctx)
		require.NoError(t, err)
		assert.Len(t, workers, 1)
		worker := workers[0]
		assert.Equal(t, wStatus1.GetWorkerId(), worker.GetPublicId())
		assert.Equal(t, wStatus1.Address, worker.CanonicalAddress())
		assert.Empty(t, worker.Name)
		assert.Equal(t, worker.ReportedStatus.CreateTime, worker.CreateTime)
		assert.Equal(t, worker.LastConnectionUpdate(), worker.UpdateTime)
		assert.Equal(t, uint32(1), worker.Version)
		assert.Empty(t, worker.Address)
		assert.Empty(t, worker.Description)
	}

	// Remove the status name, verify that it doesn't remove the resource's name.
	updatedStatus1 := servers.NewWorkerStatus(wStatus1.WorkerId,
		servers.WithAddress(wStatus1.Address))
	_, _, err = repo.UpsertWorkerStatus(ctx, updatedStatus1)
	require.NoError(t, err)
	{
		workers, err := repo.ListWorkers(ctx)
		require.NoError(t, err)
		assert.Len(t, workers, 1)
		worker := workers[0]
		// The resource's name remains untouched
		assert.Empty(t, worker.Name)
		// The ReportedStatus's name is correctly cleared
		assert.Empty(t, worker.ReportedStatus.Name)
		// The last connection update time was increased
		assert.Greater(t, worker.LastConnectionUpdate().AsTime().UnixMilli(), worker.UpdateTime.AsTime().UnixMilli())
		assert.Equal(t, worker.UpdateTime, worker.CreateTime)

		assert.Equal(t, updatedStatus1.GetWorkerId(), worker.GetPublicId())
		assert.Equal(t, updatedStatus1.Address, worker.CanonicalAddress())
		assert.Equal(t, worker.ReportedStatus.CreateTime, worker.CreateTime)
		assert.Equal(t, uint32(1), worker.Version)
		assert.Empty(t, worker.Address)
		assert.Empty(t, worker.Description)
	}

	failureCases := []struct {
		name      string
		status    *servers.WorkerStatus
		errAssert func(*testing.T, error)
	}{
		{
			name: "no address",
			status: servers.NewWorkerStatus("worker_with_no_address",
				servers.WithName("worker_with_no_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "invalid id",
			status: servers.NewWorkerStatus("short",
				servers.WithAddress("someaddress"),
				servers.WithName("worker_with_short_id")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.IsCheckConstraintError(err))
			},
		},
		{
			name: "no id",
			status: servers.NewWorkerStatus("",
				servers.WithAddress("anotheraddress"),
				servers.WithName("no_address")),
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
	}
	for _, tc := range failureCases {
		t.Run(fmt.Sprintf("Failures %s", tc.name), func(t *testing.T) {
			_, _, err = repo.UpsertWorkerStatus(ctx, tc.status)
			assert.Error(t, err)
			tc.errAssert(t, err)

			// Still only the original worker exists.
			workers, err := repo.ListWorkers(ctx)
			require.NoError(t, err)
			assert.Len(t, workers, 1)
		})
	}

	{
		anotherStatus := servers.NewWorkerStatus("another_test_worker",
			servers.WithAddress("address"))
		_, _, err = repo.UpsertWorkerStatus(ctx, anotherStatus)
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

	wStatus := servers.NewWorkerStatus("test_worker_1",
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

	_, _, err = repo.UpsertWorkerStatus(ctx, wStatus, servers.WithUpdateTags(true))
	require.NoError(err)

	wStatus = servers.NewWorkerStatus("test_worker_2",
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
	_, _, err = repo.UpsertWorkerStatus(ctx, wStatus, servers.WithUpdateTags(true))
	require.NoError(err)

	tags, err := repo.ListTagsForWorkers(ctx, []string{"test_worker_1", "test_worker_2"})
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
	wStatus = servers.NewWorkerStatus("test_worker_2",
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
	_, _, err = repo.UpsertWorkerStatus(ctx, wStatus)
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(ctx, []string{"test_worker_1", "test_worker_2"})
	require.NoError(err)
	require.Equal(exp, tags)

	// Update tags and test again
	_, _, err = repo.UpsertWorkerStatus(ctx, wStatus, servers.WithUpdateTags(true))
	require.NoError(err)
	tags, err = repo.ListTagsForWorkers(ctx, []string{"test_worker_1", "test_worker_2"})
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

	newWorkerStatus := func(publicId string) *servers.WorkerStatus {
		result := servers.NewWorkerStatus(publicId,
			servers.WithAddress("127.0.0.1"))
		_, rowsUpdated, err := serversRepo.UpsertWorkerStatus(ctx, result)
		require.NoError(err)
		require.Equal(1, rowsUpdated)

		return result
	}

	workConf1 := newWorkerStatus("test_worker_1")
	workConf2 := newWorkerStatus("test_worker_2")
	workConf3 := newWorkerStatus("test_worker_3")

	// Sleep the default liveness time (15sec currently) +1s
	time.Sleep(time.Second * 16)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, rowsUpdated, err := serversRepo.UpsertWorkerStatus(ctx, workConf1)
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
	_, rowsUpdated, err = serversRepo.UpsertWorkerStatus(ctx, workConf2)
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

func TestRepository_CreateWorker(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	testRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testNewIdFn := func(context.Context) (string, error) {
		return "", errors.New(testCtx, errors.Internal, "test", "testNewIdFn-error")
	}

	tests := []struct {
		name            string
		setup           func() *servers.Worker
		repo            *servers.Repository
		opt             []servers.Option
		wantErr         bool
		wantErrIs       errors.Code
		wantErrContains string
	}{
		{
			name: "missing-worker",
			setup: func() *servers.Worker {
				return nil
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing worker",
		},
		{
			name: "public-id-not-empty",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				var err error
				w.PublicId, err = db.NewPublicId(servers.WorkerPrefix)
				require.NoError(t, err)
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "public id is not empty",
		},
		{
			name: "empty-scope-id",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				w.ScopeId = ""
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "org-scope-id",
			setup: func() *servers.Worker {
				w := servers.NewWorker(org.PublicId)
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "scope id must be \"global\"",
		},
		{
			name: "new-id-error",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			repo:            testRepo,
			opt:             []servers.Option{servers.WithNewIdFunc(testNewIdFn)},
			wantErr:         true,
			wantErrIs:       errors.Internal,
			wantErrContains: "testNewIdFn-error",
		},
		{
			name: "create-error",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			repo: func() *servers.Repository {
				conn, mock := db.TestSetupWithMock(t)
				writer := db.New(conn)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New(testCtx, errors.Internal, "test", "create-error"))
				mock.ExpectRollback()
				r, err := servers.NewRepository(rw, writer, kms)
				require.NoError(t, err)
				return r
			}(),
			wantErr:         true,
			wantErrContains: "unable to create worker",
		},
		{
			name: "success",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			repo: testRepo,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testWorker := tc.setup()
			got, err := tc.repo.CreateWorker(testCtx, testWorker, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrIs != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrIs), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.NotEmpty(got.PublicId)
			assert.NotEmpty(got.UpdateTime)
			assert.NotEmpty(got.CreateTime)

			found := &servers.Worker{
				Worker: &store.Worker{
					PublicId: got.PublicId,
				},
			}
			err = rw.LookupByPublicId(testCtx, found)
			require.NoError(err)
			if found.Tags == nil {
				found.Tags = []*servers.Tag{}
			}
			assert.Equal(got, found)
		})
	}
}
