// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema/internal/postgres"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// setup is a helper function for tests.
// It creates a new database using Template1, establishes an connection,
// and returns a *postgres.Postgres.
// It also returns the underlying sql.DB and connection url so tests
// can establish additional connections if necessary.
func setup(ctx context.Context, t *testing.T) (*postgres.Postgres, *sql.DB, string) {
	t.Helper()

	c, u, _, err := dbtest.StartUsingTemplate(dbtest.Postgres, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dbtest.Postgres, u)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, d.Close())
	})
	p, err := postgres.New(ctx, d)
	require.NoError(t, err)

	return p, d, u
}
