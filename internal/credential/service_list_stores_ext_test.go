// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	sstore "github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/credential/vault"
	vstore "github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStoreService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	stores := []credential.Store{
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token2", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
	}

	vaultRepo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(t, err)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	service, err := credential.NewStoreService(ctx, rw, vaultRepo, staticRepo)
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

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(credential.Store) (bool, error) {
			return true, nil
		}
		resp, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedTotalItems, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[0], cmpOpts...))

		resp2, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedTotalItems, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], stores[1], cmpOpts...))

		resp3, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedTotalItems, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], stores[2], cmpOpts...))

		resp4, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedTotalItems, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], stores[3], cmpOpts...))

		resp5, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedTotalItems, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], stores[4], cmpOpts...))

		resp6, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedTotalItems, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(l credential.Store) (bool, error) {
			return l.GetPublicId() == stores[len(stores)-1].GetPublicId(), nil
		}
		resp, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedTotalItems, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[4], cmpOpts...))

		resp2, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedTotalItems, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(l credential.Store) (bool, error) {
			return true, nil
		}
		deletedStoreId := stores[0].GetPublicId()
		_, err := vaultRepo.DeleteCredentialStore(ctx, deletedStoreId)
		require.NoError(t, err)
		stores = stores[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		// Note: this will still show up as 5 because Vault credential
		// stores are deleted asynchronously.
		require.Equal(t, resp.EstimatedTotalItems, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], stores[0], cmpOpts...))

		resp2, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedTotalItems, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], stores[1], cmpOpts...))

		deletedStoreId = stores[0].GetPublicId()
		_, err = staticRepo.DeleteCredentialStore(ctx, deletedStoreId)
		require.NoError(t, err)
		stores = stores[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedTotalItems, 4)
		require.Contains(t, resp3.DeletedIds, deletedStoreId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], stores[1], cmpOpts...))

		resp4, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedTotalItems, 4)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], stores[2], cmpOpts...))

		resp5, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, []string{prj.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedTotalItems, 4)
		require.Empty(t, resp5.Items)
	})
}
