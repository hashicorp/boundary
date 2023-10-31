// Copyright (c) HashiCorp, Inc.
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

func TestLookupWorkerByName(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	w := server.TestKmsWorker(t, conn, wrapper)
	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorkerByName(ctx, w.GetName())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w.Worker, got.Worker, protocmp.Transform()))
	})
	t.Run("not found", func(t *testing.T) {
		got, err := repo.LookupWorkerByName(ctx, "unknown_name")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("db error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		rw := db.New(conn)
		mock.ExpectQuery(`SELECT`).WillReturnError(errors.New(ctx, errors.Internal, "test", "lookup-error"))
		r, err := server.NewRepository(ctx, rw, rw, kms)
		require.NoError(t, err)
		got, err := r.LookupWorkerByName(ctx, w.GetName())
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Truef(t, errors.Match(errors.T(errors.Op("server.(Repository).LookupWorkerByName")), err), "got error %v", err)
		assert.Nil(t, got)
	})
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
		c, _, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
		c, _, err = connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	// 1 session with 1 connection
	{
		sess2 := session.TestDefaultSession(t, conn, wrapper, iam.TestRepo(t, conn, wrapper),
			session.WithDbOpts(db.WithSkipVetForWrite(true)))
		sess2, _, err = sessRepo.ActivateSession(ctx, sess2.GetPublicId(), sess2.Version, []byte("foo"))
		require.NoError(t, err)
		c, _, err := connRepo.AuthorizeConnection(ctx, sess2.GetPublicId(), w.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	t.Run("success", func(t *testing.T) {
		got, err := repo.LookupWorker(ctx, w.GetPublicId())
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(w, got, protocmp.Transform()))
		assert.Equal(t, uint32(3), got.ActiveConnectionCount())
		assert.Equal(t, map[string][]string{
			"key": {"val"},
		}, got.CanonicalTags())
		assert.Equal(t, got.CanonicalTags(), got.GetConfigTags())
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
		worker, err := repo.UpsertWorkerStatus(ctx, wStatus1)
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
		worker, err = repo.UpsertWorkerStatus(ctx, wStatus2)
		require.NoError(t, err)
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		assert.Equal(t, "config_name1", worker.Name)
		// Version does not change for status updates
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "test-version", wStatus2.ReleaseVersion)
		assert.Equal(t, "new_address", worker.GetAddress())

		// Expect this worker to be returned as it is active
		workers, err := repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithActiveWorkers(true))
		require.NoError(t, err)
		assert.Len(t, workers, 1)
		assert.Equal(t, server.KmsWorkerType.String(), workers[0].Type)

		// update again with a shutdown state
		wStatus3 := server.NewWorker(scope.Global.String(),
			server.WithAddress("new_address"), server.WithName("config_name1"),
			server.WithOperationalState("shutdown"), server.WithReleaseVersion("Boundary v0.11.0"))
		worker, err = repo.UpsertWorkerStatus(ctx, wStatus3)
		require.NoError(t, err)
		assert.Greater(t, worker.GetLastStatusTime().AsTime(), worker.GetCreateTime().AsTime())
		// Version does not change for status updates
		assert.Equal(t, uint32(1), worker.Version)
		assert.Equal(t, "shutdown", worker.GetOperationalState())

		// Should no longer see this worker in listing if we exclude shutdown workers
		workers, err = repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithActiveWorkers(true))
		require.NoError(t, err)
		assert.Len(t, workers, 0)
	})

	// Setup and use a pki worker
	var pkiWorkerKeyId string
	pkiWorker := server.TestPkiWorker(t, conn, wrapper, server.WithName("pki"), server.WithDescription("pki_description1"), server.WithTestPkiWorkerAuthorizedKeyId(&pkiWorkerKeyId))

	t.Run("update status for pki worker", func(t *testing.T) {
		wStatus1 := server.NewWorker(scope.Global.String(),
			server.WithAddress("pki_address"), server.WithDescription("pki_description2"),
			server.WithReleaseVersion("test-version"))
		worker, err := repo.UpsertWorkerStatus(ctx, wStatus1, server.WithKeyId(pkiWorkerKeyId), server.WithReleaseVersion("test-version"))
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
			workers, err := repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()})
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

		workers, err := repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()})
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

		workers, err := repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()})
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

		// Filtering out shutdown workers will remove the shutdown KMS and this shutdown worker, resulting in 2
		workers, err := repo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithActiveWorkers(true))
		require.NoError(t, err)
		assert.Len(t, workers, 2)
	})
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

	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus,
		server.WithUpdateTags(true))
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
	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus)
	require.NoError(err)
	assert.Len(t, worker1.CanonicalTags(), 1)
	assert.ElementsMatch(t, []string{"value1", "value2"}, worker1.CanonicalTags()["tag1"])

	// Update tags and test again
	worker1, err = repo.UpsertWorkerStatus(ctx, wStatus, server.WithUpdateTags(true))
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
			name:      "only-kms-type",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []server.Option{server.WithLimit(-1), server.WithWorkerType(server.KmsWorkerType)},
			wantCnt:   testLimit + 1,
			wantErr:   false,
		},
		{
			name:      "only-pki-type",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []server.Option{server.WithLimit(-1), server.WithWorkerType(server.PkiWorkerType)},
			wantCnt:   testLimit + 1,
			wantErr:   false,
		},
		{
			name:      "bad-type",
			createCnt: testLimit + 1,
			reqScopes: []string{scope.Global.String()},
			opts:      []server.Option{server.WithLimit(-1), server.WithWorkerType("foo")},
			wantErr:   true,
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
			// the purpose of these tests isn't to check liveness, so disable
			// liveness checking.
			opts := append(tt.opts, server.WithLiveness(-1))
			got, err := repo.ListWorkersUnpaginated(ctx, tt.reqScopes, opts...)
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

func TestListWorkers_WithWorkerPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	serversRepo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestPkiWorker(t, conn, wrapper)
	worker3 := server.TestKmsWorker(t, conn, wrapper)

	result, err := serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithLiveness(-1))
	require.NoError(err)
	require.Len(result, 3)

	tests := []struct {
		name       string
		workerPool []string
		want       []*server.Worker
	}{
		{
			name:       "one",
			workerPool: []string{worker1.GetPublicId()},
			want:       []*server.Worker{worker1},
		},
		{
			name:       "two",
			workerPool: []string{worker2.GetPublicId(), worker3.GetPublicId()},
			want:       []*server.Worker{worker2, worker3},
		},
		{
			name:       "none",
			workerPool: []string{},
			want:       []*server.Worker{worker1, worker2, worker3},
		},
		{
			name:       "unknown ids",
			workerPool: []string{"this_is_unknown"},
			want:       []*server.Worker{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithLiveness(-1), server.WithWorkerPool(tt.workerPool))
			require.NoError(err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestListWorkers_WithActiveWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestKmsWorker(t, conn, wrapper)
	worker3 := server.TestKmsWorker(t, conn, wrapper)

	result, err := serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()})
	require.NoError(err)
	require.Len(result, 3)

	tests := []struct {
		name      string
		upsertFn  func() (*server.Worker, error)
		wantCnt   int
		wantState string
	}{
		{
			name: "upsert-worker1-to-shutdown",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker1.GetName()),
						server.WithAddress(worker1.GetAddress()),
						server.WithOperationalState(server.ShutdownOperationalState.String()),
						server.WithReleaseVersion("Boundary v.0.11"),
						server.WithPublicId(worker1.GetPublicId())))
			},
			wantCnt:   2,
			wantState: server.ShutdownOperationalState.String(),
		},
		{
			name: "upsert-worker2-to-shutdown",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker2.GetName()),
						server.WithAddress(worker2.GetAddress()),
						server.WithOperationalState(server.ShutdownOperationalState.String()),
						server.WithReleaseVersion("Boundary v.0.11"),
						server.WithPublicId(worker2.GetPublicId())))
			},
			wantCnt:   1,
			wantState: server.ShutdownOperationalState.String(),
		},
		{
			name: "upsert-worker3-to-shutdown",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker3.GetName()),
						server.WithAddress(worker3.GetAddress()),
						server.WithOperationalState(server.ShutdownOperationalState.String()),
						server.WithReleaseVersion("Boundary v.0.11"),
						server.WithPublicId(worker3.GetPublicId())))
			},
			wantCnt:   0,
			wantState: server.ShutdownOperationalState.String(),
		},
		{ // Upsert without a release version or state and expect to get a hit- test backwards compatibility
			// Pre 0.11 workers will default to Active
			name: "upsert-no-release-version-no-state",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker3.GetName()),
						server.WithAddress(worker3.GetAddress())),
					server.WithPublicId(worker3.GetPublicId()))
			},
			wantCnt:   1,
			wantState: server.ActiveOperationalState.String(),
		},
		{ // Upsert with active status and no version and expect to get a hit- test backwards compatibility
			name: "upsert-no-release-version-active-state",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker3.GetName()),
						server.WithAddress(worker3.GetAddress()),
						server.WithOperationalState(server.ActiveOperationalState.String())),
					server.WithPublicId(worker3.GetPublicId()))
			},
			wantCnt:   1,
			wantState: server.ActiveOperationalState.String(),
		},
		{ // Upsert with unknown status and do not expect to get a hit- test worker create before status
			name: "upsert-unknown-status",
			upsertFn: func() (*server.Worker, error) {
				return serversRepo.UpsertWorkerStatus(ctx,
					server.NewWorker(scope.Global.String(),
						server.WithName(worker3.GetName()),
						server.WithAddress(worker3.GetAddress()),
						server.WithOperationalState(server.UnknownOperationalState.String())),
					server.WithPublicId(worker3.GetPublicId()))
			},
			wantCnt:   0,
			wantState: server.UnknownOperationalState.String(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker, err := tt.upsertFn()
			require.NoError(err)
			got, err := serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithActiveWorkers(true))
			require.NoError(err)
			assert.Len(t, got, tt.wantCnt)
			if len(tt.wantState) > 0 {
				assert.Equal(t, tt.wantState, worker.OperationalState)
			}
		})
	}
}

func TestListWorkers_WithLiveness(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestKmsWorker(t, conn, wrapper)
	worker3 := server.TestKmsWorker(t, conn, wrapper)

	// Sleep the default liveness time (15sec currently) +1s
	time.Sleep(time.Second * 16)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, err = serversRepo.UpsertWorkerStatus(ctx,
		server.NewWorker(scope.Global.String(),
			server.WithName(worker1.GetName()),
			server.WithAddress(worker1.GetAddress())),
		server.WithPublicId(worker1.GetPublicId()))
	require.NoError(err)

	requireIds := func(expected []string, actual []*server.Worker) {
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
	result, err := serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()})
	require.NoError(err)
	require.Len(result, 1)
	requireIds([]string{worker1.GetPublicId()}, result)

	// Upsert second server.
	_, err = serversRepo.UpsertWorkerStatus(ctx,
		server.NewWorker(scope.Global.String(),
			server.WithName(worker2.GetName()),
			server.WithAddress(worker2.GetAddress())),
		server.WithPublicId(worker2.GetPublicId()))
	require.NoError(err)

	// Static liveness. Should get two, so long as this did not take
	// more than 5s to execute.
	result, err = serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithLiveness(time.Second*5))
	require.NoError(err)
	require.Len(result, 2)
	requireIds([]string{worker1.GetPublicId(), worker2.GetPublicId()}, result)

	// Liveness disabled, should get all three workers.
	result, err = serversRepo.ListWorkersUnpaginated(ctx, []string{scope.Global.String()}, server.WithLiveness(-1))
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
