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

const (
	insertServerQuery         = "insert into server (private_id, type, address) values ($1, $2, $3)"
	selectServerQuery         = "select * from server where private_id = $1"
	expectEnumConstraintErr   = `ERROR: new row for relation "server_type_enm" violates check constraint "only_predefined_server_types_allowed" (SQLSTATE 23514)`
	expectServerConstraintErr = `ERROR: insert or update on table "server" violates foreign key constraint "server_type_enm_fkey" (SQLSTATE 23503)`
)

type testServer struct {
	PrivateId   string
	Type        string
	Description sql.NullString
	Address     string
	CreateTime  time.Time
	UpdateTime  time.Time
}

// this is a sequential test which relies on:
// 1) initializing the db using a migration up to the "priorMigration"
//
// 2) seeding the database with a test controller and worker
//
// 3) running the enum migration
//
// 4) asserting some bits about the state of the db.
//
// Tests migration:
//
//	migrations/oss/11/01_server_type_enum.up.sql
func Test_ServerEnumChanges(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	const priorMigration = 10007
	const serverEnumMigration = 11001
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
	expectedController := insertServer(ctx, t, d, "test-controller", "controller", "127.0.0.1")
	expectedWorker := insertServer(ctx, t, d, "test-worker", "worker", "127.0.0.1")

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

	// Assert servers
	actualController := selectServer(ctx, t, d, "test-controller")
	actualWorker := selectServer(ctx, t, d, "test-worker")
	require.Equal(expectedController, actualController)
	require.Equal(expectedWorker, actualWorker)

	// Assert the state of the newly created enum table
	rows, err := d.QueryContext(ctx, "select * from server_type_enm")
	require.NoError(err)

	// Inserted rows
	var actualEnm []string
	for rows.Next() {
		var a string
		require.NoError(rows.Scan(&a))
		actualEnm = append(actualEnm, a)
	}
	require.NoError(rows.Err())
	require.Equal([]string{"controller", "worker"}, actualEnm)

	// Try inserting a broken row
	result, err := d.ExecContext(ctx, "insert into server_type_enm values ($1)", "bad")
	require.EqualError(err, expectEnumConstraintErr)
	require.Nil(result)

	// Try adding a broken server type
	result, err = d.ExecContext(ctx, insertServerQuery, []any{"test-bad", "bad", "127.0.0.1"}...)
	require.EqualError(err, expectServerConstraintErr)
	require.Nil(result)

	// Add another controller and worker
	insertServer(ctx, t, d, "test-controller-new", "controller", "127.0.0.1")
	insertServer(ctx, t, d, "test-worker-new", "worker", "127.0.0.1")

	// Assert length
	var actualLen int
	row := d.QueryRowContext(ctx, "select count(*) from server")
	require.NoError(row.Scan(&actualLen))
	require.Equal(4, actualLen)
}

func insertServer(ctx context.Context, t *testing.T, d *sql.DB, privateId, serverType, address string) *testServer {
	t.Helper()
	require := require.New(t)
	execResult, err := d.ExecContext(ctx, insertServerQuery, privateId, serverType, address)
	require.NoError(err)
	rowsAffected, err := execResult.RowsAffected()
	require.NoError(err)
	require.Equal(int64(1), rowsAffected)

	return selectServer(ctx, t, d, privateId)
}

func selectServer(ctx context.Context, t *testing.T, d *sql.DB, privateId string) *testServer {
	t.Helper()
	require := require.New(t)

	serverResult := new(testServer)
	row := d.QueryRowContext(ctx, selectServerQuery, privateId)
	require.NoError(row.Scan(
		&serverResult.PrivateId,
		&serverResult.Type,
		&serverResult.Description,
		&serverResult.Address,
		&serverResult.CreateTime,
		&serverResult.UpdateTime,
	))

	return serverResult
}
