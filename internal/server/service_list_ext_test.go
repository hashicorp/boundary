// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)
	scopeIds := []string{scope.Global.String(), org.GetPublicId(), proj.GetPublicId()}

	total := 5
	var workers []*server.Worker
	for i := 0; i < total; i++ {
		workers = append(workers, server.TestKmsWorker(t, conn, wrapper))
	}

	// Run analyze to update target estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	repo, err := server.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	t.Run("ListWorkers validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err := server.ListWorkers(ctx, nil, 1, filterFunc, repo, scopeIds)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err := server.ListWorkers(ctx, []byte("some hash"), 0, filterFunc, repo, scopeIds)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err := server.ListWorkers(ctx, []byte("some hash"), -1, filterFunc, repo, scopeIds)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := server.ListWorkers(ctx, []byte("some hash"), 1, nil, repo, scopeIds)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err := server.ListWorkers(ctx, []byte("some hash"), 1, filterFunc, nil, scopeIds)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("empty scopeIds", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err := server.ListWorkers(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, nil, 1, filterFunc, tok, repo, scopeIds)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, scopeIds)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, scopeIds)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, scopeIds)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, scopeIds)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, scopeIds)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("empty scopeIds", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Target, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
			return true, nil
		}
		resp, err := server.ListWorkers(ctx, []byte("some hash"), 1, filterFunc, repo, scopeIds)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], workers[0], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], workers[1], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp3, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], workers[2], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp4, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], workers[3], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp5, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], workers[4], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp6, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
			return w.GetPublicId() == workers[len(workers)-1].GetPublicId(), nil
		}
		resp, err := server.ListWorkers(ctx, []byte("some hash"), 1, filterFunc, repo, scopeIds)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], workers[4], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, w *server.Worker) (bool, error) {
			return true, nil
		}
		deletedWorkerId := workers[0].GetPublicId()
		_, err := repo.DeleteWorker(ctx, deletedWorkerId)
		require.NoError(t, err)
		workers = workers[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := server.ListWorkers(ctx, []byte("some hash"), 1, filterFunc, repo, scopeIds)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], workers[0], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], workers[1], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		deletedWorkerId = workers[0].GetPublicId()
		_, err = repo.DeleteWorker(ctx, deletedWorkerId)
		require.NoError(t, err)
		workers = workers[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedWorkerId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], workers[1], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp4, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], workers[2], cmpopts.IgnoreUnexported(server.Worker{}, store.Worker{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp5, err := server.ListWorkersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, scopeIds)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
