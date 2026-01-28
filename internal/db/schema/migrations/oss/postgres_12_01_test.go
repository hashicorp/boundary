// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// Tests migration:
//
//	migrations/oss/12/01_timestamp_sub_funcs.up.sql
func TestWtSubSeconds(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	d := testSetupDb(ctx, t)

	// Test by subtracing a day from the test date
	sourceTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
	require.NoError(err)
	expectedTime := sourceTime.Add(time.Second * -86400)

	var actualTime time.Time
	row := d.QueryRowContext(ctx, "select wt_sub_seconds($1, $2)", 86400, sourceTime)
	require.NoError(row.Scan(&actualTime))
	require.True(expectedTime.Equal(actualTime))
}

func testSetupDb(ctx context.Context, t *testing.T) *sql.DB {
	t.Helper()
	require := require.New(t)
	const targetMigration = 12001

	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": targetMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   targetMigration,
				DatabaseSchemaVersion: targetMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)
	return d
}
