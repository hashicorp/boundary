// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"slices"
	"testing"
	"time"

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStoreRepository_List(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	stores := []credential.Store{
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token2", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(stores)

	repo, err := credential.NewStoreRepository(ctx, rw, rw)
	require.NoError(err)

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

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.List(ctx, nil, nil, 1)
			require.ErrorContains(err, "missing project ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.List(ctx, []string{prj.PublicId}, nil, 0)
			require.ErrorContains(err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.List(ctx, []string{prj.PublicId}, nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.List(ctx, []string{prj.PublicId}, stores[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores[1:], cmpOpts...))
	})
}

func TestStoreRepository_ListRefresh(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	stores := []credential.Store{
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), "http://some-addr", "some-token2", "some-accessor"),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
		static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId()),
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(stores)

	repo, err := credential.NewStoreRepository(ctx, rw, rw)
	require.NoError(err)

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

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, []string{prj.PublicId}, time.Time{}, nil, 1)
			require.ErrorContains(err, "missing updated after time")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, nil, fiveDaysAgo, nil, 1)
			require.ErrorContains(err, "missing project ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, nil, 0)
			require.ErrorContains(err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, stores[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores[1:], cmpOpts...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, stores[len(stores)-1].GetUpdateTime().AsTime(), nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores[:len(stores)-1], cmpOpts...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, stores[len(stores)-1].GetUpdateTime().AsTime(), stores[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, stores[1:len(stores)-1], cmpOpts...))
	})
}

func TestStoreRepository_EstimatedCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	repo, err := credential.NewStoreRepository(ctx, rw, rw)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some stores
	staticStores := static.TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)
	_ = vault.TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(4, numItems)

	// Delete a store
	_, err = staticRepo.DeleteCredentialStore(ctx, staticStores[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(3, numItems)
}

func TestRepository_ListDeletedStoreIds(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	// Note: we're not testing vault credential stores, because they're deleted
	// asynchronously.
	staticStore := static.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	repo, err := credential.NewStoreRepository(ctx, rw, rw)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	_, err = staticRepo.DeleteCredentialStore(ctx, staticStore.GetPublicId())
	require.NoError(err)

	// Expect one entry
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{staticStore.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
}
