// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialStoreRepository_ListDeletedIds(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	staticStores := static.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

	repo, err := credential.NewCredentialStoreRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)

	// Delete a static credential store
	// NOTE: Deleting a vault credential store doesn't immediately
	// delete it, so testing this behaviour for a vault credential store
	// is kept out of the scope of this test.
	_, err = staticRepo.DeleteCredentialStore(ctx, staticStores[0].GetPublicId())
	require.NoError(err)

	// Expect one entry
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Equal([]string{staticStores[0].GetPublicId()}, deletedIds)

	// Try again with the time set to now, expect no entries
	deletedIds, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
}

func TestCredentialStoreRepository_EstimatedCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	repo, err := credential.NewCredentialStoreRepository(ctx, rw)
	require.NoError(err)
	require.NotNil(repo)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some credential stores
	_ = vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	staticStores := static.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(4, numItems)

	// Delete a static store
	_, err = staticRepo.DeleteCredentialStore(ctx, staticStores[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(3, numItems)

	// NOTE: Deleting a vault credential store doesn't immediately
	// delete it, so testing this behaviour for a vault credential store
	// is kept out of the scope of this test.
}

func TestCredentialStoreRepository_Now(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	ctx := context.Background()
	repo, err := credential.NewCredentialStoreRepository(ctx, rw)
	require.NoError(t, err)

	now, err := repo.Now(ctx)
	require.NoError(t, err)
	// Check that it's within 1 second of now according to the system
	// If this is flaky... just increase the limit 😬.
	assert.True(t, now.Before(time.Now().Add(time.Second)))
	assert.True(t, now.After(time.Now().Add(-time.Second)))
}
