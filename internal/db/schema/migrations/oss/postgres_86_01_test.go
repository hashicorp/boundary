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
	insertWorkerQuery79 = "insert into server_worker (public_id, scope_id, type) values ($1, 'global', 'pki')"
	selectWorkerQuery79 = "select public_id, local_storage_state from server_worker where public_id = $1"
	priorMigration      = 85001
	currentMigration    = 86001
)

type testWorker79 struct {
	LocalStorageState string
	PublicId          string
}

func Test_WorkerLocalStorageStateChanges(t *testing.T) {
	t.Parallel()
	require := require.New(t)
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
	execResult, err := d.ExecContext(ctx, insertWorkerQuery79, "test-worker-79")
	require.NoError(err)
	rowsAffected, err := execResult.RowsAffected()
	require.NoError(err)
	require.Equal(int64(1), rowsAffected)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
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
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// Assert worker has been migrated and received default state of 'unknown'
	actualWorker := new(testWorker79)
	row := d.QueryRowContext(ctx, selectWorkerQuery79, "test-worker-79")
	require.NoError(row.Scan(
		&actualWorker.PublicId,
		&actualWorker.LocalStorageState,
	))
	require.Equal("unknown", actualWorker.LocalStorageState)
}
