// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/authtoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
	fiveDaysAgo := time.Now()
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(context.Background())
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	var allTokens []*authtoken.AuthToken
	for i := 0; i < 5; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		at.Token = ""
		at.KeyId = ""
		allTokens = append(allTokens, at)
	}

	repo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allTokens)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(authtoken.AuthToken{}, store.AuthToken{}, timestamp.Timestamp{}, timestamppb.Timestamp{})
	cmpIgnoreFieldsOpts := cmpopts.IgnoreFields(authtoken.AuthToken{}, "Token", "KeyId")

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.List(ctx, nil, 1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.List(ctx, []byte("some hash"), 0, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.List(ctx, []byte("some hash"), -1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := authtoken.List(ctx, []byte("some hash"), 1, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.List(ctx, []byte("some hash"), 1, filterFunc, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.List(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have an auth token resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have an auth token resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			_, err := authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthToken, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have an auth token resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
			return true, nil
		}
		resp, err := authtoken.List(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allTokens[0], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp2, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allTokens[1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp3, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allTokens[2], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp4, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allTokens[3], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp5, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allTokens[4], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new auth tokens
		newAt1 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt2 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		t.Cleanup(func() {
			_, err = repo.DeleteAuthToken(ctx, newAt1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteAuthToken(ctx, newAt2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newAt2
		resp7, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newAt2, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get newAt1
		resp8, err := authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newAt1, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get no results
		resp9, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
			return at.GetPublicId() == allTokens[1].GetPublicId() ||
				at.GetPublicId() == allTokens[len(allTokens)-1].GetPublicId(), nil
		}
		resp, err := authtoken.List(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allTokens[1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp2, err := authtoken.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allTokens[len(allTokens)-1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// request a refresh, nothing should be returned
		resp3, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new tokens
		newAt1 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt2 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt3 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt4 := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteAuthToken(ctx, newAt1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteAuthToken(ctx, newAt2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteAuthToken(ctx, newAt3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteAuthToken(ctx, newAt4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
			return at.GetPublicId() == newAt3.GetPublicId() ||
				at.GetPublicId() == newAt1.GetPublicId(), nil
		}
		// Refresh again, should get newAt3
		resp4, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newAt3, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get newAt1
		resp5, err := authtoken.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newAt1, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, at *authtoken.AuthToken) (bool, error) {
			return true, nil
		}
		deletedAuthTokenId := allTokens[0].GetPublicId()
		_, err := repo.DeleteAuthToken(ctx, deletedAuthTokenId)
		require.NoError(t, err)
		allTokens = allTokens[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := authtoken.List(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allTokens[0], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// request remaining results
		resp2, err := authtoken.ListPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, allTokens[1:], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		deletedAuthTokenId = allTokens[0].GetPublicId()
		_, err = repo.DeleteAuthToken(ctx, deletedAuthTokenId)
		require.NoError(t, err)
		allTokens = allTokens[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := authtoken.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedAuthTokenId)
		require.Empty(t, resp3.Items)
	})
}
