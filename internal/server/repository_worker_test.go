// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	tgstore "github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDeleteWorker(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	ctx := context.Background()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	type args struct {
		worker *server.Worker
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
				worker: server.TestKmsWorker(t, conn, wrapper),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				worker: func() *server.Worker {
					w := server.Worker{Worker: &store.Worker{}}
					return &w
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "server.(Repository).DeleteWorker: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				worker: func() *server.Worker {
					w := server.Worker{Worker: &store.Worker{}}
					id, err := db.NewPublicId(ctx, "w")
					require.NoError(t, err)
					w.PublicId = id
					return &w
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "server.(Repository).DeleteWorker: delete failed for worker with workerId:",
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

func TestLookupWorkerIdByKeyId(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(ctx, scope.Global.String(), kms.WithRandomReader(rand.Reader)))
	repo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	var workerKeyId string
	w := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&workerKeyId))
	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorkerIdByKeyId(ctx, workerKeyId)
		require.NoError(t, err)
		assert.Equal(t, w.PublicId, got)
	})
	t.Run("not found", func(t *testing.T) {
		got, err := repo.LookupWorkerIdByKeyId(ctx, "unknown_key")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("db error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
		r, err := server.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		got, err := r.LookupWorkerIdByKeyId(ctx, "somekey")
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Truef(t, errors.Match(errors.T(errors.Op("server.(Repository).LookupWorkerIdByKeyId")), err), "got error %v", err)
		assert.Empty(t, got)
	})
}

func TestLookupWorker(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	w := server.TestKmsWorker(t, conn, wrapper,
		server.WithName("name"),
		server.WithDescription("description"),
		server.WithAddress("address"),
		server.WithWorkerTags(&server.Tag{"key", "val"}))
	require.NoError(t, err)

	sessRepo, err := session.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := session.NewConnectionRepository(ctx, rw, rw, kms, session.WithWorkerStateDelay(0))
	require.NoError(t, err)
	// 1 session with 2 connections
	{
		composedOf := session.TestSessionParams(t, conn, wrapper, iam.TestRepo(t, conn, wrapper))
		future := timestamppb.New(time.Now().Add(time.Hour))
		exp := &timestamp.Timestamp{Timestamp: future}
		composedOf.ConnectionLimit = -1
		sess := session.TestSession(t, conn, wrapper, composedOf, session.WithDbOpts(db.WithSkipVetForWrite(true)), session.WithExpirationTime(exp))
		sess, _, err = sessRepo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte("foo"))
		require.NoError(t, err)
		c, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
		c, err = connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	// 1 session with 1 connection
	{
		sess2 := session.TestDefaultSession(t, conn, wrapper, iam.TestRepo(t, conn, wrapper),
			session.WithDbOpts(db.WithSkipVetForWrite(true)))
		sess2, _, err = sessRepo.ActivateSession(ctx, sess2.GetPublicId(), sess2.Version, []byte("foo"))
		require.NoError(t, err)
		c, err := connRepo.AuthorizeConnection(ctx, sess2.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorker(ctx, w.GetPublicId())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w, got, protocmp.Transform()))
		assert.Equal(t, uint32(3), got.ActiveConnectionCount)
		assert.Equal(t, server.Tags(map[string][]string{
			"key": {"val"},
		}), got.CanonicalTags())
		assert.Equal(t, len(got.CanonicalTags()), len(got.ConfigTags))
		for k, v := range got.CanonicalTags() {
			assert.ElementsMatch(t, v, got.ConfigTags[k])
		}
	})
	t.Run("not found", func(t *testing.T) {
		got, err := repo.LookupWorker(ctx, "w_unknownid")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("db error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`with connection_count`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "lookup-error"))
		r, err := server.NewRepository(ctx, rw, rw, kms)
		require.NoError(t, err)
		got, err := r.LookupWorker(ctx, w.GetPublicId())
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Truef(t, errors.Match(errors.T(errors.Op("server.(Repository).LookupWorker")), err), "got error %v", err)
		assert.Nil(t, got)
	})
}

func TestUpsertWorkerStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))
	repo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	t.Run("create an initial kms worker and update status", func(t *testing.T) {
		wStatus1 := server.NewWorker(scope.Global.String(),
			server.WithAddress("address"), server.WithName("config_name1"),
			server.WithDescription("kms_description1"),
		)
		worker, err := server.TestUpsertAndReturnWorker(ctx, t, wStatus1, repo)
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(worker.GetPublicId(), "w_"))
		assert.Equal(t, wStatus1.GetAddress(), worker.GetAddress())
		assert.Equal(t, "config_name1", worker.Name)
		assert.Equal(t, "kms_description1", worker.Description)
		assert.Equal(t, worker.GetLastStatusTime().AsTime(), worker.GetUpdateTime().AsTime())
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "address", worker.GetAddress())
		assert.NotNil(t, worker.ReleaseVersion)

		// update again and see updated last status time
		wStatus2 := server.NewWorker(scope.Global.String(),
			server.WithAddress("new_address"), server.WithName("config_name1"), server.WithReleaseVersion("test-version"))
		worker, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus2, repo)
		require.NoError(t, err)
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		assert.Equal(t, "config_name1", worker.Name)
		// Version does not change for status updates
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "test-version", wStatus2.ReleaseVersion)
		assert.Equal(t, "new_address", worker.GetAddress())

		// Expect this worker to be returned as it is active
		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		assert.Len(t, workers, 1)
		assert.Equal(t, server.KmsWorkerType.String(), workers[0].Type)

		// update again with a shutdown state
		wStatus3 := server.NewWorker(scope.Global.String(),
			server.WithAddress("new_address"), server.WithName("config_name1"),
			server.WithOperationalState("shutdown"), server.WithReleaseVersion("Boundary v0.11.0"))
		worker, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus3, repo)
		require.NoError(t, err)
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		// Version does not change for status updates
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "shutdown", worker.GetOperationalState())
		assert.Equal(t, server.UnknownLocalStorageState.String(), worker.GetLocalStorageState())

		// update again with available local storage state
		wStatus4 := server.NewWorker(scope.Global.String(),
			server.WithAddress("new_address"), server.WithName("config_name1"),
			server.WithOperationalState("shutdown"), server.WithReleaseVersion("Boundary v0.11.0"),
			server.WithLocalStorageState("available"))
		worker, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus4, repo)
		require.NoError(t, err)
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		// Version does not change for status updates
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, server.AvailableLocalStorageState.String(), worker.GetLocalStorageState())

		// Check that this worker now returns in the shutdown state
		workers, err = repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		assert.Equal(t, "shutdown", workers[0].GetOperationalState())
	})

	// Setup and use a pki worker
	var pkiWorkerKeyId string
	pkiWorker := server.TestPkiWorker(t, conn, wrapper, server.WithName("pki"), server.WithDescription("pki_description1"), server.WithTestPkiWorkerAuthorizedKeyId(&pkiWorkerKeyId))

	t.Run("update status for pki worker", func(t *testing.T) {
		wStatus1 := server.NewWorker(scope.Global.String(),
			server.WithAddress("pki_address"), server.WithDescription("pki_description2"),
			server.WithReleaseVersion("test-version"))
		worker, err := server.TestUpsertAndReturnWorker(ctx, t, wStatus1, repo, server.WithKeyId(pkiWorkerKeyId), server.WithReleaseVersion("test-version"))
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(worker.GetPublicId(), "w_"))
		assert.Equal(t, wStatus1.GetAddress(), worker.GetAddress())
		assert.Equal(t, "pki", worker.Name)
		assert.Equal(t, "pki_description1", worker.Description) // PKI workers don't update description via status
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		assert.Equal(t, worker.GetLastStatusTime().AsTime(), worker.GetUpdateTime().AsTime())
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "pki_address", worker.GetAddress())
		assert.Equal(t, "test-version", worker.ReleaseVersion)
		assert.Equal(t, server.PkiWorkerType.String(), worker.Type)
	})

	failureCases := []struct {
		name      string
		repo      *server.Repository
		status    *server.Worker
		options   []server.Option
		errAssert func(*testing.T, error)
	}{
		{
			name: "conflicting name with pki",
			repo: repo,
			status: server.NewWorker(scope.Global.String(),
				server.WithName(pkiWorker.GetName()),
				server.WithAddress("someaddress")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.NotUnique), err), err)
			},
		},
		{
			name: "no address",
			repo: repo,
			status: server.NewWorker(scope.Global.String(),
				server.WithName("worker_with_no_address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "cant specify public id",
			repo: repo,
			status: func() *server.Worker {
				w := server.NewWorker(scope.Global.String(),
					server.WithName("worker_with_no_address"),
					server.WithAddress("workeraddress"))
				w.PublicId = "w_specified"
				return w
			}(),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "no name or key id",
			repo: repo,
			status: server.NewWorker(scope.Global.String(),
				server.WithAddress("no_name_address")),
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
			status: server.NewWorker("",
				server.WithAddress("address"),
				server.WithName("config_name1")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
			},
		},
		{
			name: "database failure",
			repo: func() *server.Repository {
				conn, mock := db.TestSetupWithMock(t)
				rw := db.New(conn)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New(context.Background(), errors.Internal, "test", "create-error"))
				mock.ExpectRollback()
				r, err := server.NewRepository(ctx, rw, rw, kmsCache)
				require.NoError(t, err)
				return r
			}(),
			status: server.NewWorker(scope.Global.String(),
				server.WithName("database failure"),
				server.WithAddress("address")),
			errAssert: func(t *testing.T, err error) {
				t.Helper()
				assert.Error(t, err)
			},
		},
	}
	for _, tc := range failureCases {
		t.Run(fmt.Sprintf("Failures %s", tc.name), func(t *testing.T) {
			_, err = tc.repo.UpsertWorkerStatus(ctx, tc.status, tc.options...)
			assert.Error(t, err)
			tc.errAssert(t, err)

			// Still only the original PKI and KMS workers exist.
			workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
			require.NoError(t, err)
			assert.Len(t, workers, 2)
		})
	}

	t.Run("add another status", func(t *testing.T) {
		anotherStatus := server.NewWorker(scope.Global.String(),
			server.WithName("another_test_worker"),
			server.WithAddress("address"),
			server.WithReleaseVersion("Boundary v0.11.0"))
		_, err = repo.UpsertWorkerStatus(ctx, anotherStatus)
		require.NoError(t, err)

		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		assert.Len(t, workers, 3)
	})

	t.Run("name and key id provided", func(t *testing.T) {
		anotherStatus := server.NewWorker(scope.Global.String(),
			server.WithName("name-and-keyid"),
			server.WithAddress("address2"),
			server.WithReleaseVersion("Boundary v0.11.0"),
			server.WithKeyId(pkiWorkerKeyId))
		_, err = repo.UpsertWorkerStatus(ctx, anotherStatus)
		require.NoError(t, err)

		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		assert.Len(t, workers, 4)
	})

	t.Run("send shutdown status", func(t *testing.T) {
		anotherStatus := server.NewWorker(scope.Global.String(),
			server.WithName("another_test_worker"),
			server.WithAddress("address"),
			server.WithOperationalState("shutdown"),
			server.WithReleaseVersion("Boundary v0.11.0"))
		_, err = repo.UpsertWorkerStatus(ctx, anotherStatus)
		require.NoError(t, err)

		// Ensure that we find two shutdown workers
		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		assert.Len(t, workers, 4)
		numShutdown := 0
		for _, w := range workers {
			if w.OperationalState == "shutdown" {
				numShutdown++
			}
		}
		assert.Equal(t, 2, numShutdown)
	})

	t.Run("ipv4 address", func(t *testing.T) {
		status := server.NewWorker(scope.Global.String(),
			server.WithName("worker-with-ipv4-address"),
			server.WithAddress("8.8.8.8"),
			server.WithReleaseVersion("Boundary v0.11.0"))
		_, err = repo.UpsertWorkerStatus(ctx, status)
		require.NoError(t, err)

		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		require.NotEmpty(t, workers)
		var actualWorker *server.Worker
		for _, w := range workers {
			if w.Name == "worker-with-ipv4-address" {
				actualWorker = w
				break
			}
		}
		require.NotNil(t, actualWorker)
		assert.Equal(t, actualWorker.Address, "8.8.8.8")
	})

	t.Run("ipv6 address", func(t *testing.T) {
		status := server.NewWorker(scope.Global.String(),
			server.WithName("worker-with-ipv6-address"),
			server.WithAddress("2001:4860:4860:0:0:0:0:8888"),
			server.WithReleaseVersion("Boundary v0.11.0"))
		_, err = repo.UpsertWorkerStatus(ctx, status)
		require.NoError(t, err)

		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		require.NotEmpty(t, workers)
		var actualWorker *server.Worker
		for _, w := range workers {
			if w.Name == "worker-with-ipv6-address" {
				actualWorker = w
				break
			}
		}
		require.NotNil(t, actualWorker)
		assert.Equal(t, actualWorker.Address, "2001:4860:4860:0:0:0:0:8888")
	})

	t.Run("ipv6 abbreviated address", func(t *testing.T) {
		status := server.NewWorker(scope.Global.String(),
			server.WithName("worker-with-abbreviated-ipv6-address"),
			server.WithAddress("2001:4860:4860::8888"),
			server.WithReleaseVersion("Boundary v0.11.0"))
		_, err = repo.UpsertWorkerStatus(ctx, status)
		require.NoError(t, err)

		workers, err := repo.ListWorkers(ctx, []string{scope.Global.String()})
		require.NoError(t, err)
		require.NotEmpty(t, workers)
		var actualWorker *server.Worker
		for _, w := range workers {
			if w.Name == "worker-with-abbreviated-ipv6-address" {
				actualWorker = w
				break
			}
		}
		require.NotNil(t, actualWorker)
		assert.Equal(t, actualWorker.Address, "2001:4860:4860::8888")
	})
}

func TestVerifyKnownWorkers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))
	repo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	workerIds := make([]string, 0, 10)
	// Seed the repo with workers
	for i := 0; i < 10; i++ {
		w := server.TestPkiWorker(t, conn, wrapper)
		workerIds = append(workerIds, w.GetPublicId())
	}

	tests := []struct {
		name    string
		testIds []string
		wantCnt int
	}{
		{
			name:    "empty-list",
			testIds: []string{},
			wantCnt: 0,
		},
		{
			name:    "full-list",
			testIds: workerIds,
			wantCnt: 10,
		},
		{
			name:    "bogus-list",
			testIds: []string{"w_bogus1", "w_bogus2"},
			wantCnt: 0,
		},
		{
			name:    "partial-bogus-list",
			testIds: []string{"w_bogus1", "w_bogus2", workerIds[0], workerIds[1]},
			wantCnt: 2,
		},
		{
			name:    "partial-list",
			testIds: workerIds[:5],
			wantCnt: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := repo.VerifyKnownWorkers(ctx, tt.testIds)
			require.NoError(t, err)
			require.Equal(t, tt.wantCnt, len(ids))
		})
	}
}

func TestTagUpdatingListing(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	wStatus := server.NewWorker(scope.Global.String(),
		server.WithName(worker1.GetName()),
		server.WithAddress("somethingnew"),
		server.WithWorkerTags(
			&server.Tag{
				Key:   "tag1",
				Value: "value1",
			},
			&server.Tag{
				Key:   "tag1",
				Value: "value2",
			}))

	worker1, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus, repo, server.WithUpdateTags(true))
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value1", "value2"}, worker1.CanonicalTags()["tag1"])

	// Update without saying to update tags
	wStatus = server.NewWorker(scope.Global.String(),
		server.WithName(worker1.GetName()),
		server.WithAddress(worker1.GetAddress()),
		server.WithWorkerTags(
			&server.Tag{
				Key:   "tag22",
				Value: "value21",
			},
			&server.Tag{
				Key:   "tag22",
				Value: "value22",
			}))
	worker1, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus, repo)
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value1", "value2"}, worker1.CanonicalTags()["tag1"])

	// Update tags and test again
	worker1, err = server.TestUpsertAndReturnWorker(ctx, t, wStatus, repo, server.WithUpdateTags(true))
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value21", "value22"}, worker1.CanonicalTags()["tag22"])
}

func TestListWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	const testLimit = 10
	repo, err := server.NewRepository(ctx, rw, rw, kmsCache, server.WithLimit(testLimit))
	require.NoError(t, err)

	tests := []struct {
		name      string
		createCnt int
		reqScopes []string
		opts      []server.Option
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []server.Option{server.WithLimit(-1)},
			wantCnt:   testLimit*2 + 2,
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
			opts:      []server.Option{server.WithLimit(3)},
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
			w := server.NewWorker(scope.Global.String())
			db.TestDeleteWhere(t, conn, w, "true")
			for i := 0; i < tt.createCnt; i++ {
				server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{"key", "val"}))
			}
			for i := 0; i < tt.createCnt; i++ {
				server.TestPkiWorker(t, conn, wrapper)
			}
			got, err := repo.ListWorkers(ctx, tt.reqScopes, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantCnt)
			for _, worker := range got {
				switch worker.GetType() {
				case server.KmsWorkerType.String():
					canonicalTags := worker.CanonicalTags()
					assert.Len(t, canonicalTags, 1)
					require.Len(t, canonicalTags["key"], 1)
					assert.Equal(t, canonicalTags["key"][0], "val")
				case server.PkiWorkerType.String():
					assert.Empty(t, worker.CanonicalTags())
				}
			}
		})
	}
}

func TestRepository_CreateWorker(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	testRepo, err := server.NewRepository(testCtx, rw, rw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testNewIdFn := func(context.Context) (string, error) {
		return "", errors.New(testCtx, errors.Internal, "test", "testNewIdFn-error")
	}

	kmsWorker := server.TestKmsWorker(t, conn, wrapper)

	rootStorage, err := server.NewRepositoryStorage(testCtx, rw, rw, testKms)
	require.NoError(t, err)
	_, err = rotation.RotateRootCertificates(testCtx, rootStorage)
	require.NoError(t, err)

	tests := []struct {
		name            string
		setup           func() *server.Worker
		repo            *server.Repository
		reader          db.Reader
		opt             []server.Option
		wantErr         bool
		wantErrIs       errors.Code
		wantErrContains string
	}{
		{
			name: "missing-worker",
			setup: func() *server.Worker {
				return nil
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "missing worker",
		},
		{
			name: "public-id-not-empty",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				var err error
				w.PublicId, err = db.NewPublicId(testCtx, globals.WorkerPrefix)
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
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
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
			setup: func() *server.Worker {
				w := server.NewWorker(org.PublicId)
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "scope id must be \"global\"",
		},
		{
			name: "new-id-error",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			repo:            testRepo,
			opt:             []server.Option{server.WithNewIdFunc(testNewIdFn)},
			wantErr:         true,
			wantErrIs:       errors.Internal,
			wantErrContains: "testNewIdFn-error",
		},
		{
			name: "create-error",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			repo: func() *server.Repository {
				conn, mock := db.TestSetupWithMock(t)
				writer := db.New(conn)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New(testCtx, errors.Internal, "test", "create-error"))
				mock.ExpectRollback()
				r, err := server.NewRepository(testCtx, rw, writer, testKms)
				require.NoError(t, err)
				return r
			}(),
			wantErr:         true,
			wantErrContains: "unable to create worker",
		},
		{
			name: "no worker reported address",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Address = "foo"
				return w
			},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "address is not empty",
		},
		{
			name: "no last status update",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
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
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			reader: rw,
			opt: []server.Option{server.WithFetchNodeCredentialsRequest(
				func() *types.FetchNodeCredentialsRequest {
					// This happens on the worker
					fileStorage, err := file.New(testCtx)
					require.NoError(t, err)
					defer func() { fileStorage.Cleanup(testCtx) }()

					nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
					require.NoError(t, err)
					// Create request using worker id
					fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
					require.NoError(t, err)
					return fetchReq
				}(),
			)},
			repo: func() *server.Repository {
				mockConn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(testCtx, errors.Internal, "test", "no-database-key"))
				k := kms.TestKms(t, mockConn, wrapper)
				r, err := server.NewRepository(testCtx, rw, rw, k)
				require.NoError(t, err)
				return r
			}(),
			wantErr:         true,
			wantErrContains: "unable to get wrapper",
		},
		{
			name: "bad-fetch-node-req",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			reader:          rw,
			opt:             []server.Option{server.WithFetchNodeCredentialsRequest(&types.FetchNodeCredentialsRequest{})},
			repo:            testRepo,
			wantErr:         true,
			wantErrContains: "unable to authorize node",
		},
		{
			name: "unique name violation with kms worker",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Name = kmsWorker.GetName()
				return w
			},
			reader:    rw,
			repo:      testRepo,
			wantErr:   true,
			wantErrIs: errors.NotUnique,
		},
		{
			name: "success-no-options",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Name = "success"
				return w
			},
			reader: rw,
			repo:   testRepo,
		},
		// This case must follow the one above it.
		{
			name: "unique name violation with pki worker",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Name = "success"
				return w
			},
			reader:    rw,
			repo:      testRepo,
			wantErr:   true,
			wantErrIs: errors.NotUnique,
		},
		{
			name: "success-with-state",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			reader: rw,
			opt:    []server.Option{server.WithOperationalState("shutdown")},
			repo:   testRepo,
		},
		{
			name: "success-with-fetch-node-req",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Name = "success-with-fetch-node-req"
				return w
			},
			reader: rw,
			opt: []server.Option{server.WithFetchNodeCredentialsRequest(
				func() *types.FetchNodeCredentialsRequest {
					// This happens on the worker
					fileStorage, err := file.New(testCtx)
					require.NoError(t, err)
					defer func() { fileStorage.Cleanup(testCtx) }()

					nodeCreds, err := types.NewNodeCredentials(testCtx, fileStorage)
					require.NoError(t, err)
					// Create request using worker id
					fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
					require.NoError(t, err)
					return fetchReq
				}(),
			)},
			repo: testRepo,
		},
		{
			name: "success-with-controller-activation-token",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				w.Name = "success-with-controller-activation-token"
				return w
			},
			reader: rw,
			opt:    []server.Option{server.WithCreateControllerLedActivationToken(true)},
			repo:   testRepo,
		},
		{
			name: "success-with-valid-local-storage-state",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			reader: rw,
			opt:    []server.Option{server.WithLocalStorageState("available")},
			repo:   testRepo,
		},
		{
			name: "failure-with-invalid-local-storage-state",
			setup: func() *server.Worker {
				w := server.NewWorker(scope.Global.String())
				return w
			},
			reader:          rw,
			opt:             []server.Option{server.WithLocalStorageState("invalid")},
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       errors.InvalidParameter,
			wantErrContains: "invalid local storage state",
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

			found := &server.Worker{
				Worker: &store.Worker{
					PublicId: got.PublicId,
				},
			}
			err = rw.LookupByPublicId(testCtx, found)
			require.NoError(err)
			assert.Empty(cmp.Diff(got, found, protocmp.Transform()))

			opts := server.GetOpts(tc.opt...)
			if opts.WithFetchNodeCredentialsRequest != nil {
				worker := &server.WorkerAuth{
					WorkerAuth: &store.WorkerAuth{},
				}
				require.NoError(tc.reader.LookupWhere(testCtx, worker, "worker_id = ?", []any{found.PublicId}))
			}
			if opts.WithCreateControllerLedActivationToken {
				activationToken := &server.WorkerAuthServerLedActivationToken{
					WorkerAuthServerLedActivationToken: &store.WorkerAuthServerLedActivationToken{},
				}
				require.NoError(tc.reader.LookupWhere(testCtx, activationToken, "worker_id = ?", []any{found.PublicId}))
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
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	repo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	pkiCases := []struct {
		name         string
		modifyWorker func(*testing.T, *server.Worker)
		newIdFunc    func(context.Context, string, string) func(context.Context) (string, error)
		path         []string
		assertGot    func(*testing.T, *server.Worker)
		wantErr      bool
	}{
		{
			name: "update name",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Name = "foo"
			},
			path: []string{"Name"},
			assertGot: func(t *testing.T, w *server.Worker) {
				t.Helper()
				assert.Equal(t, "foo", w.GetName())
				assert.Equal(t, uint32(2), w.GetVersion())
				assert.Nil(t, w.GetLastStatusTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "update name against kms-pki",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Name = "foo"
			},
			newIdFunc: func(ctx context.Context, scopeId, name string) func(ctx context.Context) (string, error) {
				return func(ctx context.Context) (string, error) {
					return server.NewWorkerIdFromScopeAndName(ctx, scopeId, name)
				}
			},
			path:    []string{"Name"},
			wantErr: true,
		},
		{
			name: "update description",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Description = "foo"
			},
			path: []string{"Description"},
			assertGot: func(t *testing.T, w *server.Worker) {
				t.Helper()
				assert.Equal(t, "foo", w.GetDescription())
				assert.Equal(t, uint32(2), w.GetVersion())
				assert.Nil(t, w.GetLastStatusTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "update description against kms-pki",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Description = "foo"
			},
			newIdFunc: func(ctx context.Context, scopeId, name string) func(ctx context.Context) (string, error) {
				return func(ctx context.Context) (string, error) {
					return server.NewWorkerIdFromScopeAndName(ctx, scopeId, name)
				}
			},
			path:    []string{"Description"},
			wantErr: true,
		},
	}
	for _, tt := range pkiCases {
		t.Run(tt.name, func(t *testing.T) {
			name := strings.ReplaceAll(tt.name, " ", "-")
			opts := []server.Option{server.WithName(name)}
			if tt.newIdFunc != nil {
				opts = append(opts, server.WithNewIdFunc(tt.newIdFunc(ctx, scope.Global.String(), name)))
			}
			wkr := server.TestPkiWorker(t, conn, wrapper, opts...)
			defer func() {
				_, err := repo.DeleteWorker(ctx, wkr.GetPublicId())
				require.NoError(t, err)
			}()
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
		modifyWorker func(*testing.T, *server.Worker)
		path         []string
		assertGot    func(*testing.T, *server.Worker)
		wantErr      bool
	}{
		{
			name: "clear name",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Name = ""
			},
			path: []string{"Name"},
			assertGot: func(t *testing.T, w *server.Worker) {
				t.Helper()
				assert.Empty(t, w.GetName())
				assert.Nil(t, w.GetLastStatusTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
		{
			name: "clear description",
			modifyWorker: func(t *testing.T, w *server.Worker) {
				t.Helper()
				w.Description = ""
			},
			path: []string{"Description"},
			assertGot: func(t *testing.T, w *server.Worker) {
				t.Helper()
				assert.Empty(t, w.GetDescription())
				assert.Nil(t, w.GetLastStatusTime())
				assert.Greater(t, w.GetUpdateTime().AsTime(), w.GetCreateTime().AsTime())
			},
		},
	}
	for _, tt := range clearCases {
		t.Run(tt.name, func(t *testing.T) {
			wkr := server.TestPkiWorker(t, conn, wrapper)
			wkr.Name = tt.name
			wkr.Description = tt.name
			wkr, _, err := repo.UpdateWorker(ctx, wkr, 1, []string{"name", "description"})
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
		wkr := server.TestPkiWorker(t, conn, wrapper)
		wkr.Name = "version is wrong"
		result, numUpdated, err := repo.UpdateWorker(ctx, wkr, 2, []string{"name"})
		require.NoError(t, err)
		assert.Zero(t, numUpdated)
		assert.Equal(t, wkr.GetUpdateTime().AsTime(), result.GetUpdateTime().AsTime())
	})

	errorCases := []struct {
		name    string
		input   *server.Worker
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
			input:   server.TestPkiWorker(t, conn, wrapper),
			version: 1,
			wantErr: errors.T(errors.EmptyFieldMask),
		},
		{
			name:    "0 version",
			input:   server.TestPkiWorker(t, conn, wrapper),
			path:    []string{"name"},
			version: 0,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "changing kms name",
			input: func() *server.Worker {
				w := server.TestKmsWorker(t, conn, wrapper)
				w.Name = "some change"
				w.Description = ""
				w.Type = ""
				return w
			}(), path: []string{"name"},
			version: 1,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "clearing kms name",
			input: func() *server.Worker {
				w := server.TestKmsWorker(t, conn, wrapper)
				w.Name = ""
				w.Description = ""
				w.Type = ""
				return w
			}(), path: []string{"name"},
			version: 1,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "changing kms description",
			input: func() *server.Worker {
				w := server.TestKmsWorker(t, conn, wrapper)
				w.Description = "some change"
				w.Name = ""
				w.Type = ""
				return w
			}(), path: []string{"description"},
			version: 1,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "clearing kms description",
			input: func() *server.Worker {
				w := server.TestKmsWorker(t, conn, wrapper)
				w.Description = ""
				w.Name = ""
				w.Type = ""
				return w
			}(), path: []string{"description"},
			version: 1,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name: "no public id",
			input: func() *server.Worker {
				w := server.TestPkiWorker(t, conn, wrapper)
				w.PublicId = ""
				return w
			}(),
			path:    []string{"name"},
			version: 0,
			wantErr: errors.T(errors.InvalidParameter),
		},
		{
			name:    "unrecognized path",
			input:   server.TestPkiWorker(t, conn, wrapper),
			path:    []string{"UnrecognizedField"},
			version: 1,
			wantErr: errors.T(errors.InvalidFieldMask),
		},
		{
			name: "not found worker",
			input: func() *server.Worker {
				w := server.TestPkiWorker(t, conn, wrapper)
				w.PublicId = "w_notfoundworker"
				return w
			}(),
			path:    []string{"name"},
			version: 1,
			wantErr: errors.T(errors.RecordNotFound),
		},
		{
			name: "duplicate name",
			input: func() *server.Worker {
				w1 := server.TestPkiWorker(t, conn, wrapper)
				w1.Name = "somenamethatijustmadeup"
				w1, _, err := repo.UpdateWorker(ctx, w1, w1.Version, []string{"name"}, nil)
				require.NoError(t, err)
				w2 := server.TestPkiWorker(t, conn, wrapper)
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

func TestListHcpbManagedWorkers(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	repo, err := server.NewRepository(ctx, rw, rw, kms.TestKms(t, conn, wrapper))
	require.NoError(t, err)

	hcpbTag := &server.Tag{Key: server.ManagedWorkerTag, Value: "true"}

	t.Run("invalidLiveness", func(t *testing.T) {
		worker := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker.GetPublicId())
			assert.NoError(t, err)
		})

		_, err := repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker.GetName()),
				server.WithAddress(worker.GetAddress()),
			),
			server.WithPublicId(worker.GetPublicId()),
		)
		require.NoError(t, err)

		workers, err := repo.ListHcpbManagedWorkers(ctx, -10)
		require.NoError(t, err)
		require.Len(t, workers, 1)
		require.Equal(t, workers[0].PublicId, worker.GetPublicId())
		require.Equal(t, workers[0].Address, worker.GetAddress())
	})

	t.Run("outsideLivenessThreshold", func(t *testing.T) {
		worker := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker.GetPublicId())
			assert.NoError(t, err)
		})

		_, err := repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker.GetName()),
				server.WithAddress(worker.GetAddress()),
			),
			server.WithPublicId(worker.GetPublicId()),
		)
		require.NoError(t, err)

		<-time.After(2 * time.Second)
		workers, err := repo.ListHcpbManagedWorkers(ctx, time.Second)
		require.NoError(t, err)
		require.Len(t, workers, 0)
	})

	t.Run("inLivenessThreshold", func(t *testing.T) {
		worker := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker.GetPublicId())
			assert.NoError(t, err)
		})

		_, err := repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker.GetName()),
				server.WithAddress(worker.GetAddress()),
			),
			server.WithPublicId(worker.GetPublicId()),
		)
		require.NoError(t, err)

		workers, err := repo.ListHcpbManagedWorkers(ctx, time.Minute)
		require.NoError(t, err)
		require.Len(t, workers, 1)
		require.Equal(t, workers[0].PublicId, worker.GetPublicId())
		require.Equal(t, workers[0].Address, worker.GetAddress())
	})

	t.Run("multipleWorkers", func(t *testing.T) {
		// Not HCPb managed but in liveness interval.
		worker1 := server.TestKmsWorker(t, conn, wrapper)
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker1.GetPublicId())
			assert.NoError(t, err)
		})

		// HCPb managed not in liveness interval.
		worker2 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker2.GetPublicId())
			assert.NoError(t, err)
		})

		// HCPb managed in liveness interval.
		worker3 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker3.GetPublicId())
			assert.NoError(t, err)
		})

		// HCPb managed in liveness interval.
		worker4 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(hcpbTag))
		t.Cleanup(func() {
			_, err = repo.DeleteWorker(ctx, worker4.GetPublicId())
			assert.NoError(t, err)
		})

		<-time.After(2 * time.Second)

		// Update all the workers that are meant to be within the liveness
		// interval (worker1, worker3, worker4).
		_, err := repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker1.GetName()),
				server.WithAddress(worker1.GetAddress()),
			),
			server.WithPublicId(worker1.GetPublicId()),
		)
		require.NoError(t, err)

		_, err = repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker3.GetName()),
				server.WithAddress(worker3.GetAddress()),
			),
			server.WithPublicId(worker3.GetPublicId()),
		)
		require.NoError(t, err)

		_, err = repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(worker4.GetName()),
				server.WithAddress(worker4.GetAddress()),
			),
			server.WithPublicId(worker4.GetPublicId()),
		)
		require.NoError(t, err)

		// List should return worker3 and worker4.
		workers, err := repo.ListHcpbManagedWorkers(ctx, time.Second)
		require.NoError(t, err)

		exp := []server.WorkerAddress{
			{PublicId: worker3.GetPublicId(), Address: worker3.GetAddress()},
			{PublicId: worker4.GetPublicId(), Address: worker4.GetAddress()},
		}
		require.ElementsMatch(t, exp, workers)
	})
}

func TestFilterWorkers_EgressFilter(t *testing.T) {
	ctx := context.Background()
	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	var workers []*server.Worker
	for i := 0; i < 5; i++ {
		switch {
		case i%2 == 0:
			workers = append(workers, server.TestKmsWorker(t, conn, wrapper,
				server.WithName(fmt.Sprintf("test_worker_%d", i)),
				server.WithWorkerTags(&server.Tag{
					Key:   fmt.Sprintf("key%d", i),
					Value: fmt.Sprintf("value%d", i),
				})))
		default:
			workers = append(workers, server.TestPkiWorker(t, conn, wrapper,
				server.WithName(fmt.Sprintf("test_worker_%d", i)),
				server.WithWorkerTags(&server.Tag{
					Key:   "key",
					Value: "configvalue",
				})))
		}
	}

	cases := []struct {
		name        string
		in          []*server.Worker
		out         []*server.Worker
		filter      string
		errContains string
	}{
		{
			name:        "no-workers",
			in:          []*server.Worker{},
			out:         []*server.Worker{},
			filter:      "",
			errContains: "No workers are available to handle this session, or all have been filtered",
		},
		{
			name: "no-filter",
			in:   workers,
			out:  workers,
		},
		{
			name:        "filter-no-matches",
			in:          workers,
			out:         workers,
			filter:      `"/name" matches "test_worker_[13]" and "configvalue2" in "/tags/key"`,
			errContains: "No workers are available to handle this session, or all have been filtered",
		},
		{
			name:   "filter-one-match",
			in:     workers,
			out:    []*server.Worker{workers[1]},
			filter: `"/name" matches "test_worker_[12]" and "configvalue" in "/tags/key"`,
		},
		{
			name:   "filter-two-matches",
			in:     workers,
			out:    []*server.Worker{workers[1], workers[3]},
			filter: `"configvalue" in "/tags/key"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			target := &targettest.Target{
				Target: &tgstore.Target{},
			}
			if len(tc.filter) > 0 {
				target.EgressWorkerFilter = tc.filter
			}

			out, protocolWorker, err := server.FilterWorkersFn(
				ctx, nil, target, tc.in, "", nil, nil, nil,
			)
			if tc.errContains != "" {
				require.ErrorContains(err, tc.errContains)
				assert.Nil(out)
				return
			}

			require.NoError(err)
			require.Len(out, len(tc.out))
			for i, exp := range tc.out {
				assert.Equal(exp.Name, out[i].Name)
			}
			require.Nil(protocolWorker)
		})
	}
}

func TestSelectSessionWorkers(t *testing.T) {
	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(t, err)

	ctx := context.Background()

	iamRepo, err := iam.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	_, proj := iam.TestScopes(t, iamRepo)
	require.NotNil(t, proj)

	repo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	require.NotNil(t, repo)

	t.Run("noAvailableWorkers", func(t *testing.T) {
		tg, err := target.New(ctx, targettest.Subtype, proj.GetPublicId(), target.WithWorkerFilter(`"doesnt_exist" in "/tags/type"`))
		require.NoError(t, err)
		require.NotNil(t, tg)

		was, protoWorkerId, err := repo.SelectSessionWorkers(ctx, server.DefaultLiveness, tg, "", nil, nil, nil)
		require.Nil(t, was)
		require.Empty(t, protoWorkerId)
		require.ErrorContains(t, err, "No workers are available to handle this session.")
	})

	t.Run("invalidWorkerRPCGracePeriod", func(t *testing.T) {
		w1 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "worker1"}))
		require.NotNil(t, w1)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w1.GetPublicId())
			assert.NoError(t, err)
		})

		w2 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "worker2"}))
		require.NotNil(t, w2)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w2.GetPublicId())
			assert.NoError(t, err)
		})

		tg, err := target.New(ctx, targettest.Subtype, proj.GetPublicId(), target.WithWorkerFilter(`"worker1" in "/tags/type"`))
		require.NoError(t, err)
		require.NotNil(t, tg)

		was, protoWorkerId, err := repo.SelectSessionWorkers(ctx, -10, tg, "", nil, nil, nil)
		require.NoError(t, err)
		require.Empty(t, protoWorkerId)
		require.Len(t, was, 1)
		require.Equal(t, w1.GetPublicId(), was[0].PublicId)
		require.Equal(t, w1.GetAddress(), was[0].Address)
	})

	t.Run("validWorkerRPCGracePeriod", func(t *testing.T) {
		w1 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "prod"}))
		require.NotNil(t, w1)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w1.GetPublicId())
			assert.NoError(t, err)
		})

		w2 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "prod"}))
		require.NotNil(t, w2)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w2.GetPublicId())
			assert.NoError(t, err)
		})

		<-time.After(2 * time.Second)
		_, err := repo.UpsertWorkerStatus(ctx,
			server.NewWorker(
				scope.Global.String(),
				server.WithName(w1.GetName()),
				server.WithAddress(w1.GetAddress()),
			),
			server.WithPublicId(w1.GetPublicId()),
		)
		require.NoError(t, err)

		tg, err := target.New(ctx, targettest.Subtype, proj.GetPublicId(), target.WithWorkerFilter(`"prod" in "/tags/type"`))
		require.NoError(t, err)
		require.NotNil(t, tg)

		was, protoWorkerId, err := repo.SelectSessionWorkers(ctx, time.Second, tg, "", nil, nil, nil)
		require.NoError(t, err)
		require.Empty(t, protoWorkerId)
		require.Len(t, was, 1)
		require.Equal(t, w1.GetPublicId(), was[0].PublicId)
		require.Equal(t, w1.GetAddress(), was[0].Address)
	})

	t.Run("multipleWorkers", func(t *testing.T) {
		w1 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "prod"}))
		require.NotNil(t, w1)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w1.GetPublicId())
			assert.NoError(t, err)
		})

		w2 := server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "type", Value: "prod"}))
		require.NotNil(t, w2)
		t.Cleanup(func() {
			_, err := repo.DeleteWorker(ctx, w2.GetPublicId())
			assert.NoError(t, err)
		})

		tg, err := target.New(ctx, targettest.Subtype, proj.GetPublicId(), target.WithWorkerFilter(`"prod" in "/tags/type"`))
		require.NoError(t, err)
		require.NotNil(t, tg)

		was, protoWorkerId, err := repo.SelectSessionWorkers(ctx, server.DefaultLiveness, tg, "", nil, nil, nil)
		require.NoError(t, err)
		require.Empty(t, protoWorkerId)
		require.Len(t, was, 2)

		exp := []server.WorkerAddress{
			{PublicId: w1.GetPublicId(), Address: w1.GetAddress()},
			{PublicId: w2.GetPublicId(), Address: w2.GetAddress()},
		}
		require.ElementsMatch(t, exp, was)
	})
}
