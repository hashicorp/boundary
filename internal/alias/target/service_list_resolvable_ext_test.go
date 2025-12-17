// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NOTE: These tests rely on state from previous tests, so they should be run in
// order -- running some subtests on their own will result in errors. It might
// be nice for them to be refactored at some point to start with a known state
// to avoid this. At the time I'm writing this, I'm not doing that because I'm
// not sure if this was a purposeful design choice.
func TestService_ListResolvableAliases(t *testing.T) {
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
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "target1")

	var byIdResources []*target.Alias
	for i := 0; i < 5; i++ {
		r := target.TestAlias(t, rw, fmt.Sprintf("test%d.alias.by-id", i), target.WithDestinationId(tar.GetPublicId()))
		byIdResources = append(byIdResources, r)
	}
	byIdPerms := []perms.Permission{
		{
			GrantScopeId: proj.GetPublicId(),
			Resource:     resource.Target,
			Action:       action.ListResolvableAliases,
			ResourceIds:  []string{tar.GetPublicId(), "ttcp_unknownid"},
			OnlySelf:     false,
			All:          false,
		},
	}
	// Reverse since we read items in descending order (newest first)
	slices.Reverse(byIdResources)

	_, proj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar2 := tcp.TestTarget(ctx, t, conn, proj2.GetPublicId(), "target2")
	var byScopeResources []*target.Alias
	for i := 0; i < 5; i++ {
		r := target.TestAlias(t, rw, fmt.Sprintf("test%d.alias.by-scope", i), target.WithDestinationId(tar2.GetPublicId()))
		byScopeResources = append(byScopeResources, r)
	}
	byScopePerms := []perms.Permission{
		{
			GrantScopeId: proj2.GetPublicId(),
			Resource:     resource.Target,
			Action:       action.ListResolvableAliases,
			OnlySelf:     false,
			All:          true,
		},
	}

	// Test the scenario where permissions are provided to the ListResolvableAliases service,
	// but none of the permissions include grant scopes corresponding to scopes of which targets reside.
	noTargetScopePerms := []perms.Permission{
		{
			RoleScopeId:  scope.Global.String(),
			GrantScopeId: globals.GrantScopeChildren,
			Resource:     resource.Target,
			Action:       action.ListResolvableAliases,
			OnlySelf:     false,
			All:          true,
		},
		{
			RoleScopeId:  scope.Global.String(),
			GrantScopeId: scope.Global.String(),
			Resource:     resource.Target,
			Action:       action.ListResolvableAliases,
			OnlySelf:     false,
			All:          true,
		},
	}
	// Reverse since we read items in descending order (newest first)
	slices.Reverse(byScopeResources)

	org3, proj3 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar3 := tcp.TestTarget(ctx, t, conn, proj3.GetPublicId(), "target3")
	var byChildrenResources []*target.Alias
	for i := 0; i < 5; i++ {
		r := target.TestAlias(t, rw, fmt.Sprintf("test%d.alias.by-children", i), target.WithDestinationId(tar3.GetPublicId()))
		byChildrenResources = append(byChildrenResources, r)
	}
	byChildrenPerms := []perms.Permission{
		{
			RoleScopeId:       org3.GetPublicId(),
			RoleParentScopeId: scope.Global.String(),
			GrantScopeId:      globals.GrantScopeChildren,
			Resource:          resource.Target,
			Action:            action.ListResolvableAliases,
			OnlySelf:          false,
			All:               true,
		},
	}
	// Reverse since we read items in descending order (newest first)
	slices.Reverse(byChildrenResources)

	byDescendantsPerms := []perms.Permission{
		{
			RoleScopeId:  scope.Global.String(),
			GrantScopeId: globals.GrantScopeDescendants,
			Resource:     resource.Target,
			Action:       action.ListResolvableAliases,
			OnlySelf:     false,
			All:          true,
		},
	}

	repo, repoErr := target.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, repoErr)

	// Run analyze to update postgres estimates
	_, analyzeErr := sqlDB.ExecContext(ctx, "analyze")
	require.NoError(t, analyzeErr)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(target.Alias{}, store.Alias{}, timestamp.Timestamp{}, timestamppb.Timestamp{})

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliases(ctx, nil, 1, repo, byIdPerms)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliases(ctx, []byte("some hash"), 0, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliases(ctx, []byte("some hash"), -1, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, nil, byIdPerms)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing target permissions", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, nil)
			require.ErrorContains(t, err, "missing target permissions")
		})
		t.Run("no valid target permissions", func(t *testing.T) {
			t.Parallel()
			res, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, noTargetScopePerms)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Empty(t, res.Items)
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, nil, 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), 0, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), -1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, nil, repo, byIdPerms)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, tok, nil, byIdPerms)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing permissions", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, tok, repo, nil)
			require.ErrorContains(t, err, "missing permissions")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a alias resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, nil, 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 0, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), -1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()

			_, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, nil, repo, byIdPerms)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, tok, nil, byIdPerms)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing permissions", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, tok, repo, nil)
			require.ErrorContains(t, err, "missing target permissions")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a alias resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, nil, 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 0, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), -1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			_, err := target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, nil, repo, byIdPerms)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, tok, nil, byIdPerms)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing permissions", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Alias, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, tok, repo, nil)
			require.ErrorContains(t, err, "missing target permissions")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, tok, repo, byIdPerms)
			require.ErrorContains(t, err, "token did not have a alias resource type")
		})
	})

	// Build the descendants resources for the first tests
	byDescendantsResources := append([]*target.Alias{}, byChildrenResources...)
	byDescendantsResources = append(byDescendantsResources, byScopeResources...)
	byDescendantsResources = append(byDescendantsResources, byIdResources...)

	t.Run("simple pagination", func(t *testing.T) {
		cases := []struct {
			name          string
			perms         []perms.Permission
			resourceSlice []*target.Alias
			lastPageSize  int
		}{
			{
				name:          "by-id",
				perms:         byIdPerms,
				resourceSlice: byIdResources,
				lastPageSize:  1,
			},
			{
				name:          "by-scope",
				perms:         byScopePerms,
				resourceSlice: byScopeResources,
				lastPageSize:  1,
			},
			{
				name:          "by-children",
				perms:         byChildrenPerms,
				resourceSlice: byChildrenResources,
				lastPageSize:  1,
			},
			{
				name:          "by-descendants",
				perms:         byDescendantsPerms,
				resourceSlice: byDescendantsResources,
				lastPageSize:  11,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, tc.perms)
				require.NoError(t, err)
				require.NotNil(t, resp.ListToken)
				require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
				require.False(t, resp.CompleteListing)
				require.Equal(t, 15, resp.EstimatedItemCount)
				require.Empty(t, resp.DeletedIds)
				require.Len(t, resp.Items, 1)
				require.Empty(t, cmp.Diff(resp.Items[0], tc.resourceSlice[0], cmpIgnoreUnexportedOpts), "resources did not match", tc.resourceSlice, "resp", resp.Items)

				resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, resp.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
				require.False(t, resp2.CompleteListing)
				require.Equal(t, 15, resp2.EstimatedItemCount)
				require.Empty(t, resp2.DeletedIds)
				require.Len(t, resp2.Items, 1)
				require.Empty(t, cmp.Diff(resp2.Items[0], tc.resourceSlice[1], cmpIgnoreUnexportedOpts))

				resp3, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, resp2.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
				require.False(t, resp3.CompleteListing)
				require.Equal(t, 15, resp3.EstimatedItemCount)
				require.Empty(t, resp3.DeletedIds)
				require.Len(t, resp3.Items, 1)
				require.Empty(t, cmp.Diff(resp3.Items[0], tc.resourceSlice[2], cmpIgnoreUnexportedOpts))

				resp4, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 1, resp3.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
				require.False(t, resp4.CompleteListing)
				require.Equal(t, 15, resp4.EstimatedItemCount)
				require.Empty(t, resp4.DeletedIds)
				require.Len(t, resp4.Items, 1)
				require.Empty(t, cmp.Diff(resp4.Items[0], tc.resourceSlice[3], cmpIgnoreUnexportedOpts))

				resp5, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), tc.lastPageSize, resp4.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
				require.True(t, resp5.CompleteListing)
				require.Equal(t, 15, resp5.EstimatedItemCount)
				require.Empty(t, resp5.DeletedIds)
				require.Len(t, resp5.Items, tc.lastPageSize)
				require.Empty(t, cmp.Diff(resp5.Items[0], tc.resourceSlice[4], cmpIgnoreUnexportedOpts))

				// Finished initial pagination phase, request refresh
				// Expect no results.
				resp6, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp5.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
				require.True(t, resp6.CompleteListing)
				require.Equal(t, 15, resp6.EstimatedItemCount)
				require.Empty(t, resp6.DeletedIds)
				require.Empty(t, resp6.Items)

				// Create some new aliases
				newR1 := target.TestAlias(t, rw, "first.new.alias", target.WithDestinationId(tc.resourceSlice[0].GetDestinationId()))
				newR2 := target.TestAlias(t, rw, "second.new.alias", target.WithDestinationId(tc.resourceSlice[0].GetDestinationId()))
				t.Cleanup(func() {
					_, err := repo.DeleteAlias(ctx, newR1.GetPublicId())
					require.NoError(t, err)
					_, err = repo.DeleteAlias(ctx, newR2.GetPublicId())
					require.NoError(t, err)
					// Run analyze to update count estimate
					_, err = sqlDB.ExecContext(ctx, "analyze")
					require.NoError(t, err)
				})
				// Run analyze to update count estimate
				_, err = sqlDB.ExecContext(ctx, "analyze")
				require.NoError(t, err)

				// Refresh again, should get newR2
				resp7, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp6.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
				require.False(t, resp7.CompleteListing)
				require.Equal(t, 17, resp7.EstimatedItemCount)
				require.Empty(t, resp7.DeletedIds)
				require.Len(t, resp7.Items, 1)
				require.Empty(t, cmp.Diff(resp7.Items[0], newR2, cmpIgnoreUnexportedOpts))

				// Refresh again, should get newR1
				resp8, err := target.ListResolvableAliasesRefreshPage(ctx, []byte("some hash"), 1, resp7.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
				require.True(t, resp8.CompleteListing)
				require.Equal(t, 17, resp8.EstimatedItemCount)
				require.Empty(t, resp8.DeletedIds)
				require.Len(t, resp8.Items, 1)
				require.Empty(t, cmp.Diff(resp8.Items[0], newR1, cmpIgnoreUnexportedOpts))

				// Refresh again, should get no results
				resp9, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp8.ListToken, repo, tc.perms)
				require.NoError(t, err)
				require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
				require.True(t, resp9.CompleteListing)
				require.Equal(t, 17, resp9.EstimatedItemCount)
				require.Empty(t, resp9.DeletedIds)
				require.Empty(t, resp9.Items)
			})
		}
	})

	t.Run("simple pagination with destination id changes - id", func(t *testing.T) {
		firstUpdatedA := byScopeResources[0]
		// this no longer has the destination id that has permissions
		firstUpdatedA.DestinationId = tar.GetPublicId()
		firstUpdatedA, _, err := repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
		require.NoError(t, err)
		byScopeResources = byScopeResources[1:]
		t.Cleanup(func() {
			firstUpdatedA.DestinationId = tar2.GetPublicId()
			firstUpdatedA, _, err := repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
			require.NoError(t, err)
			byScopeResources = append([]*target.Alias{firstUpdatedA}, byScopeResources...)
		})

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byScopePerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 15)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byScopeResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 3, resp.ListToken, repo, byScopePerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 15)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, byScopeResources[1:], cmpIgnoreUnexportedOpts))

		secondA := byScopeResources[0]
		// this no longer has the destination id that has permissions
		secondA.DestinationId = tar.GetPublicId()
		secondA, _, err = repo.UpdateAlias(ctx, secondA, secondA.GetVersion(), []string{"DestinationId"})
		require.NoError(t, err)
		byScopeResources = byScopeResources[1:]
		t.Cleanup(func() {
			secondA.DestinationId = tar2.GetPublicId()
			secondA, _, err := repo.UpdateAlias(ctx, secondA, secondA.GetVersion(), []string{"DestinationId"})
			require.NoError(t, err)
			byScopeResources = append([]*target.Alias{secondA}, byScopeResources...)
		})

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp2.ListToken, repo, byScopePerms)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 15)
		require.Contains(t, resp3.DeletedIds, secondA.GetPublicId())
		require.Empty(t, resp3.Items)
	})

	t.Run("simple pagination with destination id changes - children", func(t *testing.T) {
		firstUpdatedA := byChildrenResources[0]
		// this no longer has the destination id that has permissions
		firstUpdatedA.DestinationId = tar.GetPublicId()
		firstUpdatedA, _, err := repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
		require.NoError(t, err)
		byChildrenResources = byChildrenResources[1:]
		t.Cleanup(func() {
			firstUpdatedA.DestinationId = tar3.GetPublicId()
			firstUpdatedA, _, err := repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
			require.NoError(t, err)
			byChildrenResources = append([]*target.Alias{firstUpdatedA}, byChildrenResources...)
		})

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byChildrenPerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 15)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byChildrenResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 3, resp.ListToken, repo, byChildrenPerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 15)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, byChildrenResources[1:], cmpIgnoreUnexportedOpts))
	})

	// We have to re-build the expected set of resources as the original slices
	// have been updated with updated values
	byDescendantsResources = append([]*target.Alias{}, byChildrenResources...)
	byDescendantsResources = append(byDescendantsResources, byScopeResources...)
	byDescendantsResources = append(byDescendantsResources, byIdResources...)

	t.Run("simple pagination with destination id changes - descendants", func(t *testing.T) {
		firstUpdatedA := byDescendantsResources[0]
		// this no longer has the destination id that has permissions
		firstUpdatedA.DestinationId = tar.GetPublicId()
		firstUpdatedA, _, err := repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
		require.NoError(t, err)
		// Descendants will keep permissions for everything so we don't elide
		// one here, but we need to increment the version number to match
		byDescendantsResources[0] = firstUpdatedA
		t.Cleanup(func() {
			firstUpdatedA.DestinationId = tar3.GetPublicId()
			firstUpdatedA, _, err = repo.UpdateAlias(ctx, firstUpdatedA, firstUpdatedA.GetVersion(), []string{"DestinationId"})
			require.NoError(t, err)
			byDescendantsResources[0] = firstUpdatedA
		})

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byDescendantsPerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 15)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byDescendantsResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results -- we should see all, because descendants
		// is going to maintain permissions
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 14, resp.ListToken, repo, byDescendantsPerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 15)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 14)
		require.Empty(t, cmp.Diff(resp2.Items, byDescendantsResources[1:], cmpIgnoreUnexportedOpts))
	})

	t.Run("simple pagination with deletion - id", func(t *testing.T) {
		deletedAliasId := byIdResources[0].GetPublicId()
		_, err := repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byIdResources = byIdResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byIdPerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, 14, resp.EstimatedItemCount)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byIdResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 8, resp.ListToken, repo, byIdPerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, 14, resp2.EstimatedItemCount)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, byIdResources[1:], cmpIgnoreUnexportedOpts))

		deletedAliasId = byIdResources[0].GetPublicId()
		_, err = repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byIdResources = byIdResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp2.ListToken, repo, byIdPerms)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, 13, resp3.EstimatedItemCount)
		require.Contains(t, resp3.DeletedIds, deletedAliasId)
		require.Empty(t, resp3.Items)
	})

	t.Run("simple pagination with deletion - children", func(t *testing.T) {
		deletedAliasId := byChildrenResources[0].GetPublicId()
		_, err := repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byChildrenResources = byChildrenResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byChildrenPerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, 12, resp.EstimatedItemCount)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byChildrenResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 8, resp.ListToken, repo, byChildrenPerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, 12, resp2.EstimatedItemCount)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, byChildrenResources[1:], cmpIgnoreUnexportedOpts))

		deletedAliasId = byChildrenResources[0].GetPublicId()
		_, err = repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byChildrenResources = byChildrenResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp2.ListToken, repo, byChildrenPerms)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, 11, resp3.EstimatedItemCount)
		require.Contains(t, resp3.DeletedIds, deletedAliasId)
		require.Empty(t, resp3.Items)
	})

	// We have to re-build the expected set of resources as the original slices
	// have been updated with updated values again
	byDescendantsResources = append([]*target.Alias{}, byChildrenResources...)
	byDescendantsResources = append(byDescendantsResources, byScopeResources...)
	byDescendantsResources = append(byDescendantsResources, byIdResources...)

	t.Run("simple pagination with deletion - descendants", func(t *testing.T) {
		deletedAliasId := byDescendantsResources[0].GetPublicId()
		_, err := repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byDescendantsResources = byDescendantsResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := target.ListResolvableAliases(ctx, []byte("some hash"), 1, repo, byDescendantsPerms)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, 10, resp.EstimatedItemCount)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], byDescendantsResources[0], cmpIgnoreUnexportedOpts))

		// request remaining results
		resp2, err := target.ListResolvableAliasesPage(ctx, []byte("some hash"), 13, resp.ListToken, repo, byDescendantsPerms)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, 10, resp2.EstimatedItemCount)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 9)
		require.Empty(t, cmp.Diff(resp2.Items, byDescendantsResources[1:], cmpIgnoreUnexportedOpts))

		deletedAliasId = byDescendantsResources[0].GetPublicId()
		_, err = repo.DeleteAlias(ctx, deletedAliasId)
		require.NoError(t, err)
		byDescendantsResources = byDescendantsResources[1:]

		// Run analyze to update count estimate
		_, err = sqlDB.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := target.ListResolvableAliasesRefresh(ctx, []byte("some hash"), 1, resp2.ListToken, repo, byDescendantsPerms)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, 9, resp3.EstimatedItemCount)
		require.Contains(t, resp3.DeletedIds, deletedAliasId)
		require.Empty(t, resp3.Items)
	})
}
