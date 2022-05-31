package servers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDeleteWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	ctx := context.Background()

	type args struct {
		worker *servers.Worker
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				worker: servers.TestWorker(t, conn, wrapper),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				worker: func() *servers.Worker {
					w := servers.Worker{Worker: &store.Worker{}}
					return &w
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "servers.(Repository).DeleteWorker: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				worker: func() *servers.Worker {
					w := servers.Worker{Worker: &store.Worker{}}
					id, err := db.NewPublicId("w")
					require.NoError(t, err)
					w.PublicId = id
					return &w
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "servers.(Repository).DeleteWorker: delete failed for worker with workerId:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteWorker(ctx, tt.args.worker.Worker.PublicId)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)

				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			// Validate that the worker no longer exists
			err = rw.LookupByPublicId(ctx, tt.args.worker)
			assert.ErrorIs(err, dbw.ErrRecordNotFound)
		})
	}
}

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
	t.Run("db error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
		r, err := servers.NewRepository(rw, rw, kms)
		require.NoError(t, err)
		got, err := r.LookupWorkerByWorkerReportedName(ctx, w.GetWorkerReportedName())
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Truef(t, errors.Match(errors.T(errors.Op("servers.(Repository).LookupWorkerByWorkerReportedName")), err), "got error %v", err)
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
		got, err := repo.LookupWorker(ctx, "w_unknownid")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("db error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
		r, err := servers.NewRepository(rw, rw, kms)
		require.NoError(t, err)
		got, err := r.LookupWorker(ctx, w.GetPublicId())
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Truef(t, errors.Match(errors.T(errors.Op("servers.(Repository).LookupWorker")), err), "got error %v", err)
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
		repo      *servers.Repository
		status    *servers.Worker
		errAssert func(*testing.T, error)
	}{
		{
			name: "no address",
			repo: repo,
			status: servers.NewWorkerForStatus(scope.Global.String(),
				servers.WithName("worker_with_no_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "cant specifying public id",
			repo: repo,
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
			repo: repo,
			status: servers.NewWorkerForStatus(scope.Global.String(),
				servers.WithAddress("no_name_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name:   "no status",
			repo:   repo,
			status: nil,
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "empty scope",
			repo: repo,
			status: servers.NewWorkerForStatus("",
				servers.WithAddress("address"),
				servers.WithName("config_name1")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "providing api tags",
			repo: repo,
			status: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String(),
					servers.WithWorkerTags(&servers.Tag{Key: "test", Value: "test"}))
				w.WorkerReportedAddress = "some_address"
				w.WorkerReportedName = "providing api tags"
				return w
			}(),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "database failure",
			repo: func() *servers.Repository {
				conn, mock := db.TestSetupWithMock(t)
				rw := db.New(conn)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "create-error"))
				mock.ExpectRollback()
				r, err := servers.NewRepository(rw, rw, kms)
				require.NoError(t, err)
				return r
			}(),
			status: servers.NewWorkerForStatus(scope.Global.String(),
				servers.WithName("database failure"),
				servers.WithAddress("address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.Error(t, err)
			},
		},
	}
	for _, tc := range failureCases {
		t.Run(fmt.Sprintf("Failures %s", tc.name), func(t *testing.T) {
			_, err = tc.repo.UpsertWorkerStatus(ctx, tc.status)
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
			name: "no worker reported address",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				w.WorkerReportedAddress = "foo"
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "worker reported address is not empty",
		},
		{
			name: "no worker reported name",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				w.WorkerReportedName = "foo"
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "worker reported name is not empty",
		},
		{
			name: "no last status update",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				w.LastStatusTime = timestamp.Now()
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "last status time is not nil",
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
			assert.Equal(got, found)
		})
	}
}
