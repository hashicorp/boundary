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
	makeWorkerQuery             = "insert into server_worker (public_id, scope_id, type) values ($1, 'global', 'pki')"
	insertWorkerTagsQuery       = "insert into server_worker_tag (worker_id, key, value, source) values ($1, $2, $3, $4)"
	selectWorkerApiTagsQuery    = "select key, value from server_worker_api_tag where worker_id = $1"
	selectWorkerConfigTagsQuery = "select key, value from server_worker_config_tag where worker_id = $1"
)

type testWorkerTags struct {
	Key   string
	Value string
}

func Test_WorkerTagTableSplit(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	const priorMigration = 92001
	const serverEnumMigration = 94001
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
	execResult, err := d.ExecContext(ctx, makeWorkerQuery, "test-worker")
	require.NoError(err)
	rowsAffected, err := execResult.RowsAffected()
	require.NoError(err)
	require.Equal(int64(1), rowsAffected)
	execResult, err = d.ExecContext(ctx, insertWorkerTagsQuery, "test-worker", "key1", "value1", "api")
	require.NoError(err)
	rowsAffected, err = execResult.RowsAffected()
	require.NoError(err)
	require.Equal(int64(1), rowsAffected)
	execResult, err = d.ExecContext(ctx, insertWorkerTagsQuery, "test-worker", "key2", "value2", "configuration")
	require.NoError(err)
	rowsAffected, err = execResult.RowsAffected()
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

	// Check that the tags have been moved to the new tables
	apiTags := new(testWorkerTags)
	row := d.QueryRowContext(ctx, selectWorkerApiTagsQuery, "test-worker")
	require.NoError(row.Scan(
		&apiTags.Key,
		&apiTags.Value,
	))
	require.Equal("key1", apiTags.Key)
	require.Equal("value1", apiTags.Value)

	configTags := new(testWorkerTags)
	row = d.QueryRowContext(ctx, selectWorkerConfigTagsQuery, "test-worker")
	require.NoError(row.Scan(
		&configTags.Key,
		&configTags.Value,
	))
	require.Equal("key2", configTags.Key)
	require.Equal("value2", configTags.Value)
}
