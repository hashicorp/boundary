// Copyright (c) HashiCorp, Inc.
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
