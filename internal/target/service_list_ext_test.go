// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Note: this file imports the targettest package. The only
// reason this doesn't cause an import cycle is because this is
// an "external" test package.
func TestService_List(t *testing.T) {
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
	fiveDaysAgo := time.Now()

	total := 5
	var targets []target.Target
	for i := 0; i < total; i++ {
		targets = append(targets, targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i)))
	}

	// since we sort descending, we need to reverse targets
	slices.Reverse(targets)

	// Run analyze to update target estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				GrantScopeId: proj1.PublicId,
				Resource:     resource.Target,
				Action:       action.List,
				All:          true,
			},
		}),
	)
	require.NoError(t, err)

	cmpOpts := cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.List(ctx, nil, 1, filterFunc, repo)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.List(ctx, []byte("some hash"), 0, filterFunc, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.List(ctx, []byte("some hash"), -1, filterFunc, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := target.List(ctx, []byte("some hash"), 1, nil, repo)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.List(ctx, []byte("some hash"), 1, filterFunc, nil)
			require.ErrorContains(t, err, "missing repo")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, nil, 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), 1, nil, tok, repo)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a target resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, nil, 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), 1, nil, tok, repo)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a target resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, nil, 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			_, err := target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, t target.Target) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo)
			require.ErrorContains(t, err, "token did not have a target resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, t target.Target) (bool, error) {
			return true, nil
		}
		resp, err := target.List(ctx, []byte("some hash"), 1, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[0], cmpOpts))

		resp2, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], targets[1], cmpOpts))

		resp3, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], targets[2], cmpOpts))

		resp4, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], targets[3], cmpOpts))

		resp5, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], targets[4], cmpOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new targets
		newT1 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-5")
		newT2 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-6")
		t.Cleanup(func() {
			_, err = repo.DeleteTarget(ctx, newT1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteTarget(ctx, newT2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update target estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newT2
		resp7, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newT2, cmpOpts))

		// Refresh again, should get newT1
		resp8, err := target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newT1, cmpOpts))

		// Refresh again, should get no results
		resp9, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, t target.Target) (bool, error) {
			return t.GetPublicId() == targets[1].GetPublicId() ||
				t.GetPublicId() == targets[len(targets)-1].GetPublicId(), nil
		}
		resp, err := target.List(ctx, []byte("some hash"), 1, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[1], cmpOpts))

		resp2, err := target.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], targets[len(targets)-1], cmpOpts))

		// request a refresh, nothing should be returned
		resp3, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new targets
		newT1 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-7")
		newT2 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-8")
		newT3 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-9")
		newT4 := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-10")
		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteTarget(ctx, newT1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteTarget(ctx, newT2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteTarget(ctx, newT3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteTarget(ctx, newT4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update target estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, t target.Target) (bool, error) {
			return t.GetPublicId() == newT3.GetPublicId() ||
				t.GetPublicId() == newT1.GetPublicId(), nil
		}
		// Refresh again, should get newT3
		resp4, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newT3, cmpOpts))

		// Refresh again, should get newT1
		resp5, err := target.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newT1, cmpOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, t target.Target) (bool, error) {
			return true, nil
		}
		deletedTargetId := targets[0].GetPublicId()
		_, err := repo.DeleteTarget(ctx, deletedTargetId)
		require.NoError(t, err)
		targets = targets[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.List(ctx, []byte("some hash"), 1, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[0], cmpOpts))

		// request remaining results
		resp2, err := target.ListPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, targets[1:], cmpOpts))

		deletedTargetId = targets[0].GetPublicId()
		_, err = repo.DeleteTarget(ctx, deletedTargetId)
		require.NoError(t, err)
		targets = targets[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedTargetId)
		require.Empty(t, resp3.Items)
	})

	t.Run("simple pagination with updated items", func(t *testing.T) {
		filterFunc := func(_ context.Context, t target.Target) (bool, error) {
			return true, nil
		}
		resp, err := target.List(ctx, []byte("some hash"), 3, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 3)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 3)
		require.Empty(t, cmp.Diff(resp.Items, targets, cmpOpts))

		// create a new target and run analyze to update target estimate
		newTarget := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "proj1-new")
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp2, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], newTarget, cmpOpts))
	})
}
