// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
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
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	total := 5
	var targets []target.Target
	for i := 0; i < total; i++ {
		targets = append(targets, targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i)))
	}

	// Run analyze to update target estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				ScopeId:  proj1.PublicId,
				Resource: resource.Target,
				Action:   action.List,
				All:      true,
			},
		}),
	)
	require.NoError(t, err)

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(t target.Target) (bool, error) {
			return true, nil
		}
		resp, err := target.List(ctx, []byte("some hash"), 1, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedTotalItems, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[0], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedTotalItems, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], targets[1], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp3, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedTotalItems, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], targets[2], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp4, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedTotalItems, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], targets[3], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp5, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedTotalItems, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], targets[4], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp6, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedTotalItems, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(t target.Target) (bool, error) {
			return t.GetPublicId() == targets[len(targets)-1].GetPublicId(), nil
		}
		resp, err := target.List(ctx, []byte("some hash"), 1, filterFunc, repo)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedTotalItems, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[4], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo)
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
		filterFunc := func(t target.Target) (bool, error) {
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
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedTotalItems, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], targets[0], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp2, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedTotalItems, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], targets[1], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		deletedTargetId = targets[0].GetPublicId()
		_, err = repo.DeleteTarget(ctx, deletedTargetId)
		require.NoError(t, err)
		targets = targets[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedTotalItems, 3)
		require.Contains(t, resp3.DeletedIds, deletedTargetId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], targets[1], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp4, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedTotalItems, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], targets[2], cmpopts.IgnoreUnexported(targettest.Target{}, store.Target{}, timestamp.Timestamp{}, timestamppb.Timestamp{})))

		resp5, err := target.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedTotalItems, 3)
		require.Empty(t, resp5.Items)
	})
}
