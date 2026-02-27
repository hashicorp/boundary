// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

func TestAlias(t *testing.T, rw *db.Db, alias string, opt ...Option) *Alias {
	t.Helper()
	ctx := context.Background()

	a, err := NewAlias(ctx, "global", alias, opt...)
	require.NoError(t, err)
	a.PublicId, err = newAliasId(ctx)
	require.NoError(t, err)
	require.NoError(t, rw.Create(ctx, a, db.WithDebug(true)))
	return a
}

// TODO: Replace TestAlias with this when migrating to the TransactionManager
func TestNewAlias(t *testing.T, txm db.TransactionManager, alias string, opt ...Option) *Alias {
	t.Helper()
	ctx := context.Background()

	a, err := NewAlias(ctx, "global", alias, opt...)
	require.NoError(t, err)
	a.PublicId, err = newAliasId(ctx)
	require.NoError(t, err)
	require.NoError(t, txm.Writer().Create(ctx, a, db.WithDebug(true)))
	return a
}
