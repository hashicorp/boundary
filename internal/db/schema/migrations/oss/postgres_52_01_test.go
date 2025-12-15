// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

const (
	insertWorkerQuery = "insert into server_worker (public_id, scope_id, type) values ($1, 'global', 'pki')"
	selectWorkerQuery = "select public_id, operational_state from server_worker where public_id = $1"
)

type testWorker struct {
	OperationalState string
	PublicId         string
}

func Test_WorkerOperationalStateChanges(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	const priorMigration = 51001
	const serverEnumMigration = 52001
	dialect := dbtest.Postgres
	ctx := context.Background()

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
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
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// Seed the data
	execResult, err := d.ExecContext(ctx, insertWorkerQuery, "test-worker")
	require.NoError(err)
	rowsAffected, err := execResult.RowsAffected()
	require.NoError(err)
	require.Equal(int64(1), rowsAffected)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": serverEnumMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
	state, err = m.CurrentState(ctx)
	require.NoError(err)

	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   serverEnumMigration,
				DatabaseSchemaVersion: serverEnumMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// Assert worker has been migrated and received default state of 'active'
	actualWorker := new(testWorker)
	row := d.QueryRowContext(ctx, selectWorkerQuery, "test-worker")
	require.NoError(row.Scan(
		&actualWorker.PublicId,
		&actualWorker.OperationalState,
	))
	require.Equal("active", actualWorker.OperationalState)
}
