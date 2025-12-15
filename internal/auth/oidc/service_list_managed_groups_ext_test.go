// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListManagedGroups(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice1.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	oidcMgs := []*oidc.ManagedGroup{
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
		oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter),
	}

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			oidc.ManagedGroup{},
			store.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	var mgs []auth.ManagedGroup
	for _, mg := range oidcMgs {
		mgs = append(mgs, mg)
	}
	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(mgs)

	// Run analyze to update host estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	t.Run("ListManagedGroups validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroups(ctx, nil, 1, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 0, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroups(ctx, []byte("some hash"), -1, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
	})
	t.Run("ListManagedGroupsPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a managed group resource type")
		})
	})
	t.Run("ListManagedGroupsRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a managed group resource type")
		})
	})
	t.Run("ListManagedGroupsRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing credential store id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.ManagedGroup, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a managed group resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, auth.ManagedGroup) (bool, error) {
			return true, nil
		}
		resp, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], mgs[0], cmpOpts...))

		resp2, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], mgs[1], cmpOpts...))

		resp3, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], mgs[2], cmpOpts...))

		resp4, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], mgs[3], cmpOpts...))

		resp5, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], mgs[4], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new mgs
		mg1 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		mg2 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		t.Cleanup(func() {
			_, err := repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get mg2
		resp7, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], mg2, cmpOpts...))

		// Refresh again, should get mg1
		resp8, err := oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], mg1, cmpOpts...))

		// Refresh again, should get no results
		resp9, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, mg auth.ManagedGroup) (bool, error) {
			return mg.GetPublicId() == mgs[1].GetPublicId() ||
				mg.GetPublicId() == mgs[len(mgs)-1].GetPublicId(), nil
		}
		resp, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], mgs[1], cmpOpts...))

		resp2, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], mgs[len(mgs)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new mgs
		mg1 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		mg2 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		mg3 := oidc.TestManagedGroup(t, conn, authMethod, oidc.TestFakeManagedGroupFilter)
		t.Cleanup(func() {
			repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg1.GetPublicId())
			require.NoError(t, err)
			repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg2.GetPublicId())
			require.NoError(t, err)
			repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg3.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
			return mg.GetPublicId() == mg3.GetPublicId() ||
				mg.GetPublicId() == mg1.GetPublicId(), nil
		}
		// Refresh again, should get mg3
		resp4, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 8)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], mg3, cmpOpts...))

		// Refresh again, should get mg1
		resp5, err := oidc.ListManagedGroupsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 8)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], mg1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, auth.ManagedGroup) (bool, error) {
			return true, nil
		}
		deletedMGId := mgs[0].GetPublicId()
		repo.DeleteManagedGroup(ctx, org.GetPublicId(), deletedMGId)
		require.NoError(t, err)
		mgs = mgs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := oidc.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], mgs[0], cmpOpts...))

		// request remaining results
		resp2, err := oidc.ListManagedGroupsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, mgs[1:], cmpOpts...))

		deletedMGId = mgs[0].GetPublicId()
		repo.DeleteManagedGroup(ctx, org.GetPublicId(), deletedMGId)
		require.NoError(t, err)
		mgs = mgs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := oidc.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedMGId)
		require.Empty(t, resp3.Items)
	})
}
