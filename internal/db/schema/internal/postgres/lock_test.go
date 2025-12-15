// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema/internal/postgres"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// Tests that TrySharedLock:
// - can get a lock as the only connection
// - a second connection can also get the shared lock
// - a second connection cannot get an exclusive lock
func TestTrySharedLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, u := setup(ctx, t)

	err := p.TrySharedLock(ctx)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)

	p2, err := postgres.New(ctx, d2)
	require.NoError(t, err)

	err = p2.TrySharedLock(ctx)
	require.NoError(t, err)

	err = p2.TryLock(ctx)
	require.Error(t, err)
}

// Test that TryLock gets an exclusive lock and:
// - a separate connection cannot get the lock via TryLock
// - a separate connection cannot get the lock via TrySharedLock
// - a separate connection cannot get the lock via Lock
func TestTryLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, u := setup(ctx, t)

	err := p.TryLock(ctx)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)

	p2, err := postgres.New(ctx, d2)
	require.NoError(t, err)

	err = p2.TrySharedLock(ctx)
	require.Error(t, err)

	err = p2.TryLock(ctx)
	require.Error(t, err)

	ctx2, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()

	err = p2.Lock(ctx2)
	require.Error(t, err)
}

// Test that Lock gets an exclusive lock and:
// - a separate connection cannot get the lock via TryLock
// - a separate connection cannot get the lock via TrySharedLock
// - a separate connection cannot get the lock via Lock
func TestLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, u := setup(ctx, t)

	err := p.Lock(ctx)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)

	p2, err := postgres.New(ctx, d2)
	require.NoError(t, err)

	err = p2.TrySharedLock(ctx)
	require.Error(t, err)

	err = p2.TryLock(ctx)
	require.Error(t, err)

	ctx2, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()

	err = p2.Lock(ctx2)
	require.Error(t, err)
}

// Test the Unlock:
// - can unlock a lock granted via TryLock
// - can unlock a lock granted via Lock
func TestUnlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, u := setup(ctx, t)

	err := p.Lock(ctx)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)

	p2, err := postgres.New(ctx, d2)
	require.NoError(t, err)

	// cannot get lock since p has it.
	err = p2.TryLock(ctx)
	require.Error(t, err)

	// clear lock on p
	err = p.Unlock(ctx)
	require.NoError(t, err)

	// p2 can now get lock
	err = p2.TryLock(ctx)
	require.NoError(t, err)

	// p can not get the lock now
	err = p.TryLock(ctx)
	require.Error(t, err)

	// clear lock on p2
	err = p2.Unlock(ctx)
	require.NoError(t, err)

	// p can now get lock
	err = p.TryLock(ctx)
	require.NoError(t, err)
}

// Test that UnlockShared
// - can unlock a lock granted by TrySharedLock
func TestUnlockShared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, u := setup(ctx, t)

	err := p.TrySharedLock(ctx)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)

	p2, err := postgres.New(ctx, d2)
	require.NoError(t, err)

	err = p2.TryLock(ctx)
	require.Error(t, err)

	err = p.UnlockShared(ctx)
	require.NoError(t, err)

	err = p2.TryLock(ctx)
	require.NoError(t, err)
}
