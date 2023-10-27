// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	orgDbWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := ldap.TestAuthMethod(t, conn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1"})

	testGrpNames := []string{"test-admin", "test-users"}
	ldapMgs := []*ldap.ManagedGroup{
		ldap.TestManagedGroup(t, conn, authMethod, testGrpNames),
		ldap.TestManagedGroup(t, conn, authMethod, testGrpNames),
		ldap.TestManagedGroup(t, conn, authMethod, testGrpNames),
		ldap.TestManagedGroup(t, conn, authMethod, testGrpNames),
		ldap.TestManagedGroup(t, conn, authMethod, testGrpNames),
	}

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	require.NotNil(t, ldapRepo)

	var a []auth.ManagedGroup
	for _, l := range ldapMgs {
		a = append(a, l)
	}

	// 	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ldap.ManagedGroup{},
			ldapstore.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}
	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := ldap.ListManagedGroups(ctx, nil, 1, filterFunc, ldapRepo, "")
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 0, filterFunc, ldapRepo, "")
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := ldap.ListManagedGroups(ctx, []byte("some hash"), -1, filterFunc, ldapRepo, "")
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 1, nil, ldapRepo, "")
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, nil, "")
			require.ErrorContains(t, err, "missing repo")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Account, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = ldap.ListManagedGroupsRefresh(ctx, nil, 1, filterFunc, tok, ldapRepo, "")
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Account, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, ldapRepo, "")
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Account, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, ldapRepo, "")
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Account, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, nil, tok, ldapRepo, "")
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			_, err = ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, ldapRepo, "")
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, mg auth.ManagedGroup) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Account, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, "")
			require.ErrorContains(t, err, "missing repo")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, auth.ManagedGroup) (bool, error) {
			return true, nil
		}
		resp, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, 5, resp.EstimatedItemCount)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], a[0], cmpOpts...))

		resp2, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], a[1], cmpOpts...))

		resp3, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], a[2], cmpOpts...))

		resp4, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], a[3], cmpOpts...))

		resp5, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], a[4], cmpOpts...))

		resp6, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, acc auth.ManagedGroup) (bool, error) {
			return acc.GetPublicId() == a[len(a)-1].GetPublicId(), nil
		}
		resp, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], a[4], cmpOpts...))

		resp2, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
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
		filterFunc := func(context.Context, auth.ManagedGroup) (bool, error) {
			return true, nil
		}
		deletedManagedGroupId := a[0].GetPublicId()
		_, err := ldapRepo.DeleteManagedGroup(ctx, org.GetPublicId(), deletedManagedGroupId)
		require.NoError(t, err)
		a = a[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := ldap.ListManagedGroups(ctx, []byte("some hash"), 1, filterFunc, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], a[0], cmpOpts...))

		resp2, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], a[1], cmpOpts...))

		deletedManagedGroupId = a[0].GetPublicId()
		delNum, err := ldapRepo.DeleteManagedGroup(ctx, org.GetPublicId(), deletedManagedGroupId)
		assert.Equal(t, 1, delNum)
		require.NoError(t, err)
		a = a[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedManagedGroupId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], a[1], cmpOpts...))

		resp4, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], a[2], cmpOpts...))

		resp5, err := ldap.ListManagedGroupsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, ldapRepo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
