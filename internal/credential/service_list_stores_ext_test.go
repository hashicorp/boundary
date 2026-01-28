// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	sstore "github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/credential/vault"
	vstore "github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeReader struct {
	db.Reader
}

type fakeWriter struct {
	db.Writer
}

func TestNewStoreService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := credential.NewStoreRepository(ctx, &fakeReader{}, &fakeWriter{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-reader", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreRepository(ctx, nil, &fakeWriter{})
		require.Error(t, err)
	})
	t.Run("nil-interface-reader", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreRepository(ctx, (*fakeReader)(nil), &fakeWriter{})
		require.Error(t, err)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreRepository(ctx, &fakeReader{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := credential.NewStoreRepository(ctx, &fakeReader{}, (*fakeWriter)(nil))
		require.Error(t, err)
	})
}

func TestStoreService_List(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	stores := []credential.Store{
		vault.TestCredentialStore(t, conn, wrapper, prj.PublicId, "http://some-addr", "some-token", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.PublicId),
		vault.TestCredentialStore(t, conn, wrapper, prj.PublicId, "http://some-addr", "some-token2", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.PublicId),
		static.TestCredentialStore(t, conn, wrapper, prj.PublicId),
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(stores)

	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	repo, err := credential.NewStoreRepository(ctx, rw, rw)
	require.NoError(t, err)

	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			vault.CredentialStore{},
			vstore.CredentialStore{},
			static.CredentialStore{},
			sstore.CredentialStore{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStores(ctx, nil, 1, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStores(ctx, []byte("some hash"), 0, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStores(ctx, []byte("some hash"), -1, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := credential.ListStores(ctx, []byte("some hash"), 1, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStores(ctx, []byte("some hash"), 1, filterFunc, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStores(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a credential store resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a credential store resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			_, err := credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialStore, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s credential.Store) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a credential store resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Store) (bool, error) {
			return true, nil
		}
		resp, err := credential.ListStores(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[0], cmpOpts...))

		resp2, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], stores[1], cmpOpts...))

		resp3, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], stores[2], cmpOpts...))

		resp4, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], stores[3], cmpOpts...))

		resp5, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], stores[4], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new credential stores
		newStore1 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		newStore2 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		t.Cleanup(func() {
			_, err := staticRepo.DeleteCredentialStore(ctx, newStore1.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCredentialStore(ctx, newStore2.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newStore2
		resp7, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newStore2, cmpOpts...))

		// Refresh again, should get newStore1
		resp8, err := credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newStore1, cmpOpts...))

		// Refresh again, should get no results
		resp9, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, s credential.Store) (bool, error) {
			return s.GetPublicId() == stores[1].GetPublicId() ||
				s.GetPublicId() == stores[len(stores)-1].GetPublicId(), nil
		}
		resp, err := credential.ListStores(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[1], cmpOpts...))

		resp2, err := credential.ListStoresPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], stores[len(stores)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new credential stores
		newStore1 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		newStore2 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		newStore3 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		newStore4 := static.TestCredentialStore(t, conn, wrapper, prj.PublicId)
		t.Cleanup(func() {
			_, err := staticRepo.DeleteCredentialStore(ctx, newStore1.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCredentialStore(ctx, newStore2.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCredentialStore(ctx, newStore3.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCredentialStore(ctx, newStore4.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(ctx context.Context, s credential.Store) (bool, error) {
			return s.GetPublicId() == newStore1.GetPublicId() ||
				s.GetPublicId() == newStore3.GetPublicId(), nil
		}
		// Refresh again, should get newStore3
		resp4, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newStore3, cmpOpts...))

		// Refresh again, should get newStore1
		resp5, err := credential.ListStoresRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newStore1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(ctx context.Context, s credential.Store) (bool, error) {
			return true, nil
		}
		deletedStoreId := stores[0].GetPublicId()
		_, err := staticRepo.DeleteCredentialStore(ctx, deletedStoreId)
		require.NoError(t, err)
		stores = stores[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := credential.ListStores(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[0], cmpOpts...))

		// request remaining results
		resp2, err := credential.ListStoresPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, stores[1:], cmpOpts...))

		deletedStoreId = stores[0].GetPublicId()
		_, err = staticRepo.DeleteCredentialStore(ctx, deletedStoreId)
		require.NoError(t, err)
		stores = stores[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := credential.ListStoresRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedStoreId)
		require.Empty(t, resp3.Items)
	})
}
