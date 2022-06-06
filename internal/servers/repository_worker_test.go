package servers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
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

	w := servers.TestWorker(t, conn, wrapper,
		servers.WithName("name"),
		servers.WithDescription("description"),
		servers.WithAddress("address"),
		servers.WithWorkerTags(&servers.Tag{"key", "val"}))
	w, err = repo.UpsertWorkerStatus(context.Background(),
		servers.NewWorkerForStatus(w.GetScopeId(),
			servers.WithName(w.GetWorkerReportedName()),
			servers.WithAddress(w.GetWorkerReportedAddress()),
			servers.WithWorkerTags(&servers.Tag{
				Key:   "config",
				Value: "test",
			})),
		servers.WithUpdateTags(true))
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorker(ctx, w.GetPublicId())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w, got, protocmp.Transform()))
		assert.Equal(t, map[string][]string{"key": {"val"}}, got.GetApiTags())
		assert.Equal(t, map[string][]string{"config": {"test"}}, got.GetConfigTags())
		assert.Equal(t, map[string][]string{
			"key":    {"val"},
			"config": {"test"},
		}, got.CanonicalTags())
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
			workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
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
			workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
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

func TestListWorkers(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	const testLimit = 10
	repo, err := servers.NewRepository(rw, rw, kms, servers.WithLimit(testLimit))
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name      string
		createCnt int
		reqScopes []string
		opts      []servers.Option
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []servers.Option{servers.WithLimit(-1)},
			wantCnt:   testLimit + 1,
			wantErr:   false,
		},
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			wantCnt:   testLimit,
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []servers.Option{servers.WithLimit(3)},
			wantCnt:   3,
			wantErr:   false,
		},
		{
			name:      "no-scope",
			createCnt: 1,
			reqScopes: nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := servers.NewWorker(scope.Global.String())
			db.TestDeleteWhere(t, conn, w, "true")
			for i := 0; i < tt.createCnt; i++ {
				servers.TestWorker(t, conn, wrapper)
			}
			// the purpose of these tests isn't to check liveness, so disable
			// liveness checking.
			opts := append(tt.opts, servers.WithLiveness(-1))
			got, err := repo.ListWorkers(ctx, tt.reqScopes, opts...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantCnt)
		})
	}
}

func TestListWorkers_WithLiveness(t *testing.T) {
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
	result, err := serversRepo.ListWorkers(ctx, []string{scope.Global.String()})
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
	result, err = serversRepo.ListWorkers(ctx, []string{scope.Global.String()}, servers.WithLiveness(time.Second*5))
	require.NoError(err)
	require.Len(result, 2)
	requireIds([]string{worker1.GetPublicId(), worker2.GetPublicId()}, result)

	// Liveness disabled, should get all three workers.
	result, err = serversRepo.ListWorkers(ctx, []string{scope.Global.String()}, servers.WithLiveness(-1))
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
	testKms := kms.TestKms(t, conn, wrapper)
	testRepo, err := servers.NewRepository(rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testNewIdFn := func(context.Context) (string, error) {
		return "", errors.New(testCtx, errors.Internal, "test", "testNewIdFn-error")
	}

	rootStorage, err := servers.NewRepositoryStorage(testCtx, rw, rw, testKms)
	require.NoError(t, err)
	_, err = rotation.RotateRootCertificates(testCtx, rootStorage)
	require.NoError(t, err)

	tests := []struct {
		name            string
		setup           func() *servers.Worker
		repo            *servers.Repository
		fetchReq        *types.FetchNodeCredentialsRequest
		reader          db.Reader
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
				r, err := servers.NewRepository(rw, writer, testKms)
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
			name: "no-database-key",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			reader: rw,
			fetchReq: func() *types.FetchNodeCredentialsRequest {
				// This happens on the worker
				fileStorage, err := file.New(testCtx)
				require.NoError(t, err)
				defer fileStorage.Cleanup()

				nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
				require.NoError(t, err)
				// Create request using worker id
				fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
				require.NoError(t, err)
				return fetchReq
			}(),
			repo: func() *servers.Repository {
				mockConn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "no-database-key"))
				k := kms.TestKms(t, mockConn, wrapper)
				r, err := servers.NewRepository(rw, rw, k)
				require.NoError(t, err)
				return r
			}(),
			wantErr:         true,
			wantErrContains: "unable to get wrapper",
		},
		{
			name: "bad-fetch-node-req",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			reader:          rw,
			fetchReq:        &types.FetchNodeCredentialsRequest{},
			repo:            testRepo,
			wantErr:         true,
			wantErrContains: "unable to authorize node",
		},
		{
			name: "success-with-fetch-node-req",
			setup: func() *servers.Worker {
				w := servers.NewWorker(scope.Global.String())
				return w
			},
			reader: rw,
			fetchReq: func() *types.FetchNodeCredentialsRequest {
				// This happens on the worker
				fileStorage, err := file.New(testCtx)
				require.NoError(t, err)
				defer fileStorage.Cleanup()

				nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
				require.NoError(t, err)
				// Create request using worker id
				fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
				require.NoError(t, err)
				return fetchReq
			}(),
			repo: testRepo,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testWorker := tc.setup()

			tc.opt = append(tc.opt, servers.WithFetchNodeCredentialsRequest(tc.fetchReq))

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

			if tc.fetchReq != nil {
				worker := &servers.WorkerAuth{
					WorkerAuth: &store.WorkerAuth{},
				}
				require.NoError(tc.reader.LookupWhere(testCtx, worker, "worker_id = ?", []any{found.PublicId}))
			}
		})
	}
}

func TestRepository_UpdateWorker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	repo, err := servers.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	setCases := []struct {
		name         string
		modifyWorker func(*testing.T, *servers.Worker)
		path         []string
		assertGot    func(*testing.T, *servers.Worker)
		wantErr      bool
	}{
		{
			name: "update address",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Address = "foo"
			},
			path: []string{"address"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Equal(t, "foo", w.GetAddress())
				assert.Equal(t, uint32(2), w.GetVersion())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "update name",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Name = "foo"
			},
			path: []string{"Name"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Equal(t, "foo", w.GetName())
				assert.Equal(t, uint32(2), w.GetVersion())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "update description",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Description = "foo"
			},
			path: []string{"Description"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Equal(t, "foo", w.GetDescription())
				assert.Equal(t, uint32(2), w.GetVersion())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "update worker reported name",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.WorkerReportedName = "foo"
			},
			path:    []string{"WorkerReportedName"},
			wantErr: true,
		},
		{
			name: "update worker reported name and name",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.WorkerReportedName = "foo"
				w.Name = "another"
			},
			path:    []string{"WorkerReportedName", "Name"},
			wantErr: true,
		},
		{
			name:         "Clear worker reported name",
			modifyWorker: func(t *testing.T, w *servers.Worker) {},
			path:         []string{"WorkerReportedName"},
			wantErr:      true,
		},
	}
	for _, tt := range setCases {
		t.Run(tt.name, func(t *testing.T) {
			wkr := servers.TestWorker(t, conn, wrapper)
			tt.modifyWorker(t, wkr)
			got, _, err := repo.UpdateWorker(ctx, wkr, 1, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			tt.assertGot(t, got)
		})
	}

	// Clear cases
	clearCases := []struct {
		name         string
		modifyWorker func(*testing.T, *servers.Worker)
		path         []string
		assertGot    func(*testing.T, *servers.Worker)
		wantErr      bool
	}{
		{
			name: "clear address",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Address = ""
			},
			path: []string{"address"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Empty(t, w.GetAddress())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "clear name",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Name = ""
			},
			path: []string{"Name"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Empty(t, w.GetName())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "clear description",
			modifyWorker: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				w.Description = ""
			},
			path: []string{"Description"},
			assertGot: func(t *testing.T, w *servers.Worker) {
				t.Helper()
				assert.Empty(t, w.GetDescription())
				assert.Equal(t, w.GetLastStatusTime().AsTime(), w.GetCreateTime().AsTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
	}
	for _, tt := range clearCases {
		t.Run(tt.name, func(t *testing.T) {
			wkr := servers.TestWorker(t, conn, wrapper)
			wkr.Name = tt.name
			wkr.Description = tt.name
			wkr.Address = tt.name
			wkr, _, err := repo.UpdateWorker(ctx, wkr, 1, []string{"name", "description", "address"})
			require.NoError(t, err)

			tt.modifyWorker(t, wkr)
			got, _, err := repo.UpdateWorker(ctx, wkr, 2, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			tt.assertGot(t, got)
		})
	}

	t.Run("version is wrong", func(t *testing.T) {
		wkr := servers.TestWorker(t, conn, wrapper)
		wkr.Address = "version is wrong"
		result, numUpdated, err := repo.UpdateWorker(ctx, wkr, 2, []string{"address"})
		require.NoError(t, err)
		assert.Zero(t, numUpdated)
		assert.Equal(t, wkr.GetUpdateTime().AsTime(), result.GetUpdateTime().AsTime())
	})

	errorCases := []struct {
		name    string
		input   *servers.Worker
		path    []string
		version uint32
		wantErr *errors.Template
	}{
		{
			name:    "nil worker",
			path:    []string{"name"},
			version: 1,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name:    "empty path",
			input:   servers.TestWorker(t, conn, wrapper),
			version: 1,
			wantErr: errors.T(errors.EmptyFieldMask),
		},
		{
			name:    "0 version",
			input:   servers.TestWorker(t, conn, wrapper),
			path:    []string{"name"},
			version: 0,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "no public id",
			input: func() *servers.Worker {
				w := servers.TestWorker(t, conn, wrapper)
				w.PublicId = ""
				return w
			}(),
			path:    []string{"name"},
			version: 0,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name:    "unrecognized path",
			input:   servers.TestWorker(t, conn, wrapper),
			path:    []string{"UnrecognizedField"},
			version: 1,
			wantErr: errors.T(errors.InvalidFieldMask),
		},
		{
			name: "not found worker",
			input: func() *servers.Worker {
				w := servers.TestWorker(t, conn, wrapper)
				w.PublicId = "w_notfoundworker"
				return w
			}(),
			path:    []string{"name"},
			version: 1,
			wantErr: errors.T(errors.RecordNotFound),
		},
		{
			name: "duplicate name",
			input: func() *servers.Worker {
				w1 := servers.TestWorker(t, conn, wrapper)
				w1.Name = "somenamethatijustmadeup"
				w1, _, err := repo.UpdateWorker(ctx, w1, w1.Version, []string{"name"}, nil)
				require.NoError(t, err)
				w2 := servers.TestWorker(t, conn, wrapper)
				w2.Name = w1.Name
				return w2
			}(),
			path:    []string{"name"},
			version: 1,
			wantErr: errors.T("worker with name \"somenamethatijustmadeup\" already exists"),
		},
	}
	for _, tt := range errorCases {
		t.Run(tt.name, func(t *testing.T) {
			_, updated, err := repo.UpdateWorker(ctx, tt.input, tt.version, tt.path)
			assert.Equal(t, 0, updated)
			assert.Truef(t, errors.Match(tt.wantErr, err), "Didn't match error %v", err)
		})
	}
}
