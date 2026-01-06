// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam_test

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
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListRoles(t *testing.T) {
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
	org, _ := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true))

	var allResources []*iam.Role
	for i := 0; i < 5; i++ {
		r := iam.TestRole(t, conn, org.GetPublicId())
		allResources = append(allResources, r)
	}

	repo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allResources)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(iam.Role{}, store.Role{}, timestamp.Timestamp{}, timestamppb.Timestamp{}, iam.RoleGrantScope{}, store.RoleGrantScope{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRoles(ctx, nil, 1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRoles(ctx, []byte("some hash"), 0, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRoles(ctx, []byte("some hash"), -1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := iam.ListRoles(ctx, []byte("some hash"), 1, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRoles(ctx, []byte("some hash"), 1, filterFunc, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRoles(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a role resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a role resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			_, err := iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Role, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a role resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
			return true, nil
		}
		resp, err := iam.ListRoles(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp3, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allResources[2], cmpIgnoreUnexportedOpts))

		resp4, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allResources[3], cmpIgnoreUnexportedOpts))

		resp5, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allResources[4], cmpIgnoreUnexportedOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new roles
		newR1 := iam.TestRole(t, conn, org.GetPublicId())
		newR2 := iam.TestRole(t, conn, org.GetPublicId())
		t.Cleanup(func() {
			_, err = repo.DeleteRole(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteRole(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newR2
		resp7, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newR2, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp8, err := iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newR1, cmpIgnoreUnexportedOpts))

		// Refresh again, should get no results
		resp9, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
			return r.GetPublicId() == allResources[1].GetPublicId() ||
				r.GetPublicId() == allResources[len(allResources)-1].GetPublicId(), nil
		}
		resp, err := iam.ListRoles(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListRolesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[len(allResources)-1], cmpIgnoreUnexportedOpts))

		// request a refresh, nothing should be returned
		resp3, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new tokens
		newR1 := iam.TestRole(t, conn, org.GetPublicId())
		newR2 := iam.TestRole(t, conn, org.GetPublicId())
		newR3 := iam.TestRole(t, conn, org.GetPublicId())
		newR4 := iam.TestRole(t, conn, org.GetPublicId())
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteRole(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteRole(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteRole(ctx, newR3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteRole(ctx, newR4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, r *iam.Role) (bool, error) {
			return r.GetPublicId() == newR3.GetPublicId() ||
				r.GetPublicId() == newR1.GetPublicId(), nil
		}
		// Refresh again, should get newR3
		resp4, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newR3, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp5, err := iam.ListRolesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newR1, cmpIgnoreUnexportedOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Role) (bool, error) {
			return true, nil
		}
		deletedRoleId := allResources[0].GetPublicId()
		_, err := repo.DeleteRole(ctx, deletedRoleId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := iam.ListRoles(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := iam.ListRolesPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, allResources[1:], cmpIgnoreUnexportedOpts))

		deletedRoleId = allResources[0].GetPublicId()
		_, err = repo.DeleteRole(ctx, deletedRoleId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := iam.ListRolesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedRoleId)
		require.Empty(t, resp3.Items)
	})
}

func TestService_ListUsers(t *testing.T) {
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

	us, _, err := iamRepo.ListUsers(ctx, []string{"global"})
	require.NoError(t, err)
	require.Len(t, us, 3)

	// Since ListUsers is supposed to return the newest users first, we need to
	// reverse the slice to match the order of the allResources slice.
	slices.Reverse(us)
	var allResources []*iam.User
	allResources = append(allResources, us...)

	// Create 5 users, which, with u_anon, u_recovery, and u_auth, will add
	// up to 8 users.
	for i := 0; i < 5; i++ {
		r := iam.TestUser(t, iamRepo, org.GetPublicId())
		allResources = append(allResources, r)
	}

	repo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allResources)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(iam.User{}, store.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, nil, 1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 0, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), -1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{"global"})
			require.ErrorContains(t, err, "token did not have a user resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{"global"})
			require.ErrorContains(t, err, "token did not have a user resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.User, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.User, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{"global"})
			require.ErrorContains(t, err, "token did not have a user resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return true, nil
		}
		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, len(allResources))
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 8)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp3, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 8)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allResources[2], cmpIgnoreUnexportedOpts))

		resp4, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 8)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allResources[3], cmpIgnoreUnexportedOpts))

		resp5, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 8)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allResources[4], cmpIgnoreUnexportedOpts))

		resp6, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 8)
		require.Empty(t, resp6.DeletedIds)
		require.Len(t, resp6.Items, 1)
		require.Empty(t, cmp.Diff(resp6.Items[0], allResources[5], cmpIgnoreUnexportedOpts))

		resp7, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 8)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], allResources[6], cmpIgnoreUnexportedOpts))

		resp8, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 8)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], allResources[7], cmpIgnoreUnexportedOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp9, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 8)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)

		// Create some new users
		newR1 := iam.TestUser(t, iamRepo, org.GetPublicId())
		newR2 := iam.TestUser(t, iamRepo, org.GetPublicId())
		t.Cleanup(func() {
			_, err = repo.DeleteUser(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteUser(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newR2
		resp10, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp9.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp10.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp10.CompleteListing)
		require.Equal(t, resp10.EstimatedItemCount, 10)
		require.Empty(t, resp10.DeletedIds)
		require.Len(t, resp10.Items, 1)
		require.Empty(t, cmp.Diff(resp10.Items[0], newR2, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp11, err := iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp10.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp11.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp11.CompleteListing)
		require.Equal(t, resp11.EstimatedItemCount, 10)
		require.Empty(t, resp11.DeletedIds)
		require.Len(t, resp11.Items, 1)
		require.Empty(t, cmp.Diff(resp11.Items[0], newR1, cmpIgnoreUnexportedOpts))

		// Refresh again, should get no results
		resp12, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp11.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp12.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp12.CompleteListing)
		require.Equal(t, resp12.EstimatedItemCount, 10)
		require.Empty(t, resp12.DeletedIds)
		require.Empty(t, resp12.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return r.GetPublicId() == allResources[1].GetPublicId() ||
				r.GetPublicId() == allResources[len(allResources)-1].GetPublicId(), nil
		}
		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 8)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListUsersPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 8)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[len(allResources)-1], cmpIgnoreUnexportedOpts))

		// request a refresh, nothing should be returned
		resp3, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 8)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new tokens
		newR1 := iam.TestUser(t, iamRepo, org.GetPublicId())
		newR2 := iam.TestUser(t, iamRepo, org.GetPublicId())
		newR3 := iam.TestUser(t, iamRepo, org.GetPublicId())
		newR4 := iam.TestUser(t, iamRepo, org.GetPublicId())
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteUser(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteUser(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteUser(ctx, newR3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteUser(ctx, newR4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, r *iam.User) (bool, error) {
			return r.GetPublicId() == newR3.GetPublicId() ||
				r.GetPublicId() == newR1.GetPublicId(), nil
		}
		// Refresh again, should get newR3
		resp4, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 12)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newR3, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp5, err := iam.ListUsersRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 12)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newR1, cmpIgnoreUnexportedOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return true, nil
		}
		deletedUserId := allResources[0].GetPublicId()
		_, err := repo.DeleteUser(ctx, deletedUserId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 7)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := iam.ListUsersPage(ctx, []byte("some hash"), 6, filterFunc, resp.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 7)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 6)
		require.Empty(t, cmp.Diff(resp2.Items, allResources[1:], cmpIgnoreUnexportedOpts))

		deletedUserId = allResources[0].GetPublicId()
		_, err = repo.DeleteUser(ctx, deletedUserId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId(), "global"})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 6)
		require.Contains(t, resp3.DeletedIds, deletedUserId)
		require.Empty(t, resp3.Items)
	})
}

func TestService_ListGroups(t *testing.T) {
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
	org, proj := iam.TestScopes(t, iamRepo)

	relevantScopes := []string{"global", org.GetPublicId(), proj.GetPublicId()}
	var allResources []*iam.Group
	for i := 0; i < 5; i++ {
		r := iam.TestGroup(t, conn, relevantScopes[i%len(relevantScopes)])
		allResources = append(allResources, r)
	}

	repo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allResources)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(iam.Group{}, store.Group{}, timestamp.Timestamp{}, timestamppb.Timestamp{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroups(ctx, nil, 1, filterFunc, repo, relevantScopes)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroups(ctx, []byte("some hash"), 0, filterFunc, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroups(ctx, []byte("some hash"), -1, filterFunc, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := iam.ListGroups(ctx, []byte("some hash"), 1, nil, repo, relevantScopes)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroups(ctx, []byte("some hash"), 1, filterFunc, nil, relevantScopes)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroups(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, nil, 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 1, nil, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, relevantScopes)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, relevantScopes)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a group resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, nil, 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, relevantScopes)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, relevantScopes)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a group resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			_, err := iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, relevantScopes)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, relevantScopes)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Group, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, relevantScopes)
			require.ErrorContains(t, err, "token did not have a group resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
			return true, nil
		}
		resp, err := iam.ListGroups(ctx, []byte("some hash"), 1, filterFunc, repo, relevantScopes)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp3, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allResources[2], cmpIgnoreUnexportedOpts))

		resp4, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allResources[3], cmpIgnoreUnexportedOpts))

		resp5, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allResources[4], cmpIgnoreUnexportedOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new groups
		newR1 := iam.TestGroup(t, conn, org.GetPublicId())
		newR2 := iam.TestGroup(t, conn, org.GetPublicId())
		t.Cleanup(func() {
			_, err = repo.DeleteGroup(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteGroup(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newR2
		resp7, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newR2, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp8, err := iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newR1, cmpIgnoreUnexportedOpts))

		// Refresh again, should get no results
		resp9, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
			return r.GetPublicId() == allResources[1].GetPublicId() ||
				r.GetPublicId() == allResources[len(allResources)-1].GetPublicId(), nil
		}
		resp, err := iam.ListGroups(ctx, []byte("some hash"), 1, filterFunc, repo, relevantScopes)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[len(allResources)-1], cmpIgnoreUnexportedOpts))

		// request a refresh, nothing should be returned
		resp3, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new tokens
		newR1 := iam.TestGroup(t, conn, org.GetPublicId())
		newR2 := iam.TestGroup(t, conn, org.GetPublicId())
		newR3 := iam.TestGroup(t, conn, org.GetPublicId())
		newR4 := iam.TestGroup(t, conn, org.GetPublicId())
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteGroup(ctx, newR1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteGroup(ctx, newR2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteGroup(ctx, newR3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteGroup(ctx, newR4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, r *iam.Group) (bool, error) {
			return r.GetPublicId() == newR3.GetPublicId() ||
				r.GetPublicId() == newR1.GetPublicId(), nil
		}
		// Refresh again, should get newR3
		resp4, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newR3, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp5, err := iam.ListGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newR1, cmpIgnoreUnexportedOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Group) (bool, error) {
			return true, nil
		}
		deletedGroupId := allResources[0].GetPublicId()
		_, err := repo.DeleteGroup(ctx, deletedGroupId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := iam.ListGroups(ctx, []byte("some hash"), 1, filterFunc, repo, relevantScopes)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := iam.ListGroupsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, allResources[1:], cmpIgnoreUnexportedOpts))

		deletedGroupId = allResources[0].GetPublicId()
		_, err = repo.DeleteGroup(ctx, deletedGroupId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := iam.ListGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, relevantScopes)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedGroupId)
		require.Empty(t, resp3.Items)
	})
}

func TestService_ListScopes(t *testing.T) {
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
	org := iam.TestOrg(t, iamRepo)

	repo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	var allResources []*iam.Scope
	for i := 0; i < 5; i++ {
		r := iam.TestProject(t, repo, org.GetPublicId())
		allResources = append(allResources, r)
	}

	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allResources)

	// Run analyze to update postgres estimates
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(iam.Scope{}, store.Scope{}, timestamp.Timestamp{}, timestamppb.Timestamp{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopes(ctx, nil, 1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopes(ctx, []byte("some hash"), 0, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopes(ctx, []byte("some hash"), -1, filterFunc, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := iam.ListScopes(ctx, []byte("some hash"), 1, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopes(ctx, []byte("some hash"), 1, filterFunc, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing parent ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopes(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing parent ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing parent ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing parent ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a scope resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing parent ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing parent ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a scope resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			_, err := iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing parent ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Scope, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing parent ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()})
			require.ErrorContains(t, err, "token did not have a scope resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
			return true, nil
		}
		resp, err := iam.ListScopes(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp3, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allResources[2], cmpIgnoreUnexportedOpts))

		resp4, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allResources[3], cmpIgnoreUnexportedOpts))

		resp5, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allResources[4], cmpIgnoreUnexportedOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new roles
		newP1 := iam.TestProject(t, repo, org.GetPublicId())
		newP2 := iam.TestProject(t, repo, org.GetPublicId())
		t.Cleanup(func() {
			_, err = repo.DeleteScope(ctx, newP1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteScope(ctx, newP2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newR2
		resp7, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 9)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newP2, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newR1
		resp8, err := iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 9)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newP1, cmpIgnoreUnexportedOpts))

		// Refresh again, should get no results
		resp9, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 9)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
			return r.GetPublicId() == allResources[1].GetPublicId() ||
				r.GetPublicId() == allResources[len(allResources)-1].GetPublicId(), nil
		}
		resp, err := iam.ListScopes(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[1], cmpIgnoreUnexportedOpts))

		resp2, err := iam.ListScopesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allResources[len(allResources)-1], cmpIgnoreUnexportedOpts))

		// request a refresh, nothing should be returned
		resp3, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 7) // Includes global and org
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new tokens
		newP1 := iam.TestProject(t, repo, org.GetPublicId())
		newP2 := iam.TestProject(t, repo, org.GetPublicId())
		newP3 := iam.TestProject(t, repo, org.GetPublicId())
		newP4 := iam.TestProject(t, repo, org.GetPublicId())
		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteScope(ctx, newP1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteScope(ctx, newP2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteScope(ctx, newP3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteScope(ctx, newP4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDB.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, r *iam.Scope) (bool, error) {
			return r.GetPublicId() == newP3.GetPublicId() ||
				r.GetPublicId() == newP1.GetPublicId(), nil
		}
		// Refresh again, should get newP3
		resp4, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 11)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newP3, cmpIgnoreUnexportedOpts))

		// Refresh again, should get newP1
		resp5, err := iam.ListScopesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 11)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newP1, cmpIgnoreUnexportedOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.Scope) (bool, error) {
			return true, nil
		}
		deletedScopeId := allResources[0].GetPublicId()
		_, err := repo.DeleteScope(ctx, deletedScopeId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := iam.ListScopes(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 6)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := iam.ListScopesPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 6)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, allResources[1:], cmpIgnoreUnexportedOpts))

		deletedScopeId = allResources[0].GetPublicId()
		_, err = repo.DeleteScope(ctx, deletedScopeId)
		require.NoError(t, err)
		allResources = allResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := iam.ListScopesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Contains(t, resp3.DeletedIds, deletedScopeId)
		require.Empty(t, resp3.Items)
	})
}
