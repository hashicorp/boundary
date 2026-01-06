// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListHostSets(t *testing.T) {
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
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	catalog := static.TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0]
	var sets []host.Set
	for _, set := range static.TestSets(t, conn, catalog.GetPublicId(), 5) {
		sets = append(sets, set)
	}
	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(sets)

	// Run analyze to update host set estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	repo, err := static.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			static.HostSet{},
			store.HostSet{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("ListHostSets validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSets(ctx, nil, 1, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSets(ctx, []byte("some hash"), 0, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSets(ctx, []byte("some hash"), -1, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := static.ListHostSets(ctx, []byte("some hash"), 1, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
	})
	t.Run("ListHostSetsPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})
	t.Run("ListHostSetsRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})
	t.Run("ListHostSetsRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			_, err := static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing credential store id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, host.Set) (bool, error) {
			return true, nil
		}
		resp, err := static.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], sets[0], cmpOpts...))

		resp2, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], sets[1], cmpOpts...))

		resp3, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], sets[2], cmpOpts...))

		resp4, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], sets[3], cmpOpts...))

		resp5, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], sets[4], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new hosts
		set1 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		set2 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		t.Cleanup(func() {
			_, err := repo.DeleteSet(ctx, proj1.GetPublicId(), set1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.GetPublicId(), set2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get set2
		resp7, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], set2, cmpOpts...))

		// Refresh again, should get set1
		resp8, err := static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], set1, cmpOpts...))

		// Refresh again, should get no results
		resp9, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, s host.Set) (bool, error) {
			return s.GetPublicId() == sets[1].GetPublicId() ||
				s.GetPublicId() == sets[len(sets)-1].GetPublicId(), nil
		}
		resp, err := static.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], sets[1], cmpOpts...))

		resp2, err := static.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], sets[len(sets)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new hosts
		set1 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		set2 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		set3 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		set4 := static.TestSets(t, conn, catalog.GetPublicId(), 1)[0]
		t.Cleanup(func() {
			_, err := repo.DeleteSet(ctx, proj1.GetPublicId(), set1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.GetPublicId(), set2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.GetPublicId(), set3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.GetPublicId(), set4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, s host.Set) (bool, error) {
			return s.GetPublicId() == set3.GetPublicId() ||
				s.GetPublicId() == set1.GetPublicId(), nil
		}
		// Refresh again, should get host3
		resp4, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], set3, cmpOpts...))

		// Refresh again, should get host1
		resp5, err := static.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], set1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, host.Set) (bool, error) {
			return true, nil
		}
		deletedSetId := sets[0].GetPublicId()
		_, err := repo.DeleteSet(ctx, proj1.PublicId, deletedSetId)
		require.NoError(t, err)
		sets = sets[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := static.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], sets[0], cmpOpts...))

		// request remaining results
		resp2, err := static.ListHostSetsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, sets[1:], cmpOpts...))

		deletedSetId = sets[0].GetPublicId()
		_, err = repo.DeleteSet(ctx, proj1.PublicId, deletedSetId)
		require.NoError(t, err)
		sets = sets[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := static.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedSetId)
		require.Empty(t, resp3.Items)
	})
}
