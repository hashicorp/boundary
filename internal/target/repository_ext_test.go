// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime, err := target.ListDeletedIds(repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a session
	tg := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "deleteme")
	_, err = repo.DeleteTarget(ctx, tg.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = target.ListDeletedIds(repo, ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{tg.GetPublicId()}, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = target.ListDeletedIds(repo, ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func TestEstimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := target.EstimatedCount(repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a session, expect 1 entries
	tg := targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), "target1")
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = target.EstimatedCount(repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the session, expect 0 again
	_, err = repo.DeleteTarget(ctx, tg.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = target.EstimatedCount(repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_ListTargets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)

	total := 5
	for i := 0; i < total; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i))
	}

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

	t.Run("no-options", func(t *testing.T) {
		got, err := target.ListTargets(repo, ctx)
		require.NoError(t, err)
		assert.Equal(t, total, len(got))
	})

	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		page1, err := target.ListTargets(
			repo,
			context.Background(),
			target.WithLimit(2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		page2, err := target.ListTargets(
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page1[1].GetPublicId(), page1[1].GetUpdateTime().AsTime()),
		)
		require.NoError(err)
		require.Len(page2, 2)
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, err := target.ListTargets(
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page2[1].GetPublicId(), page2[1].GetUpdateTime().AsTime()),
		)
		require.NoError(err)
		require.Len(page3, 1)
		for _, item := range append(page1, page2...) {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		}
		page4, err := target.ListTargets(
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page3[0].GetPublicId(), page3[0].GetUpdateTime().AsTime()),
		)
		require.NoError(err)
		require.Empty(page4)

		// Update the first session and check that it gets listed subsequently
		page1[0].SetName("new-name")
		_, _, err = repo.UpdateTarget(ctx, page1[0], page1[0].GetVersion(), []string{"name"})
		require.NoError(err)
		page5, err := target.ListTargets(
			repo,
			context.Background(),
			target.WithLimit(2),
			target.WithStartPageAfterItem(page3[0].GetPublicId(), page3[0].GetUpdateTime().AsTime()),
		)
		require.NoError(err)
		require.Len(page5, 1)
		require.Equal(page5[0].GetPublicId(), page1[0].GetPublicId())
	})
}

func TestRepository_ListTargets_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, proj1 := iam.TestScopes(t, iamRepo)
	_, proj2 := iam.TestScopes(t, iamRepo)

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj1.GetPublicId(), fmt.Sprintf("proj1-%d", i))
		total++
		targettest.TestNewTestTarget(ctx, t, conn, proj2.GetPublicId(), fmt.Sprintf("proj2-%d", i))
		total++
	}

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				ScopeId:  proj1.PublicId,
				Resource: resource.Target,
				Action:   action.List,
				All:      true,
			},
			{
				ScopeId:  proj2.PublicId,
				Resource: resource.Target,
				Action:   action.List,
				All:      true,
			},
		}),
	)
	require.NoError(t, err)

	got, err := target.ListTargets(repo, ctx)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
}

func TestRepository_ListRoles_Above_Default_Count(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, proj := iam.TestScopes(t, iamRepo)

	numToCreate := db.DefaultLimit + 5
	var total int
	for i := 0; i < numToCreate; i++ {
		targettest.TestNewTestTarget(ctx, t, conn, proj.GetPublicId(), fmt.Sprintf("proj1-%d", i), target.WithAddress("1.2.3.4"))
		total++
	}
	require.Equal(t, numToCreate, total)

	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms,
		target.WithPermissions([]perms.Permission{
			{
				ScopeId:  proj.PublicId,
				Resource: resource.Target,
				Action:   action.List,
				All:      true,
			},
		}))
	require.NoError(t, err)

	got, err := target.ListTargets(repo, ctx, target.WithLimit(numToCreate))
	require.NoError(t, err)
	assert.Equal(t, total, len(got))

	for _, tar := range got {
		assert.Equal(t, "1.2.3.4", tar.GetAddress())
	}
}
