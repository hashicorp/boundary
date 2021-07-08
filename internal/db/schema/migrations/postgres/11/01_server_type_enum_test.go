package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

const (
	expectEnumConstraintErr   = `pq: new row for relation "server_type_enm" violates check constraint "only_predefined_server_types_allowed"`
	expectServerConstraintErr = `db.DoTx: servers.UpsertServer:Upsert: db.Exec: insert or update on table "server" violates foreign key constraint "server_type_enm_fkey": integrity violation: error #1003`
)

// this is a sequential test which relies on:
// 1) initializing the db using a migration up to the "priorMigration"
//
// 2) seeding the database with a test controller and worker
//
// 3) running the enum migration
//
// 4) asserting some bits about the state of the db.
func Test_ServerEnumChanges(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	const priorMigration = 10007
	const serverEnumMigration = 11001
	dialect := "postgres"
	ctx := context.Background()

	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := sql.Open(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	oState := schema.TestCloneMigrationStates(t)
	nState := schema.TestCreatePartialMigrationState(oState["postgres"], priorMigration)
	oState["postgres"] = nState

	m, err := schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	require.NoError(m.RollForward(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	require.Equal(priorMigration, state.DatabaseSchemaVersion)
	require.False(state.Dirty)

	// okay, now we can seed the database with test data
	conn, err := gorm.Open(dialect, u)
	require.NoError(err)
	rootWrapper := db.TestWrapper(t)
	repo := servers.TestRepo(t, conn, rootWrapper)

	// Seed the data
	origController := &servers.Server{
		PrivateId: "test-controller",
		Type:      "controller",
		Address:   "127.0.0.1",
	}
	_, _, err = repo.UpsertServer(ctx, origController)
	require.NoError(err)

	origWorker := &servers.Server{
		PrivateId: "test-worker",
		Type:      "worker",
		Address:   "127.0.0.1",
		Tags: map[string]*servers.TagValues{
			"tag": {
				Values: []string{"value1", "value2"},
			},
		},
	}
	_, _, err = repo.UpsertServer(ctx, origWorker, servers.WithUpdateTags(true))
	require.NoError(err)

	// Read the servers back
	expectedControllers, err := repo.ListServers(ctx, servers.ServerTypeController)
	require.NoError(err)
	require.Len(expectedControllers, 1)

	expectedWorkers, err := repo.ListServers(ctx, servers.ServerTypeWorker)
	require.NoError(err)
	require.Len(expectedWorkers, 1)

	// now we're ready for the migration we want to test.
	oState = schema.TestCloneMigrationStates(t)
	nState = schema.TestCreatePartialMigrationState(oState["postgres"], serverEnumMigration)
	oState["postgres"] = nState

	m, err = schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	require.NoError(m.RollForward(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(err)
	require.Equal(serverEnumMigration, state.DatabaseSchemaVersion)
	require.False(state.Dirty)

	t.Log("current migration version: ", state.DatabaseSchemaVersion)

	// Assert servers
	actualControllers, err := repo.ListServers(ctx, servers.ServerTypeController)
	require.NoError(err)
	require.Len(actualControllers, 1)
	require.Equal(expectedControllers, actualControllers)

	actualWorkers, err := repo.ListServers(ctx, servers.ServerTypeWorker)
	require.NoError(err)
	require.Len(actualWorkers, 1)
	require.Equal(expectedWorkers, actualWorkers)

	// Assert the state of the newly created enum table
	rows, err := d.QueryContext(ctx, "select * from server_type_enm")
	require.NoError(err)

	// Column types
	colTypes, err := rows.ColumnTypes()
	require.NoError(err)
	require.Len(colTypes, 1)
	require.Equal("TEXT", colTypes[0].DatabaseTypeName())
	require.Equal("name", colTypes[0].Name())
	if nullable, ok := colTypes[0].Nullable(); ok {
		require.Equal(false, nullable)
	}

	// Inserted rows
	var actualEnm []string
	for rows.Next() {
		var a string
		require.NoError(rows.Scan(&a))
		actualEnm = append(actualEnm, a)
	}
	require.Equal([]string{"controller", "worker"}, actualEnm)

	// Try inserting a broken row
	result, err := d.ExecContext(ctx, "insert into server_type_enm values ($1)", "bad")
	require.EqualError(err, expectEnumConstraintErr)
	require.Nil(result)

	// Try adding a broken server type
	badServer := &servers.Server{
		PrivateId: "test-bad",
		Type:      "bad",
		Address:   "127.0.0.1",
	}
	_, rowsUpdated, err := repo.UpsertServer(ctx, badServer)
	require.EqualError(err, expectServerConstraintErr)
	require.Zero(rowsUpdated)

	// Add another controller and worker
	newController := &servers.Server{
		PrivateId: "test-controller-new",
		Type:      "controller",
		Address:   "127.0.0.1",
	}
	_, _, err = repo.UpsertServer(ctx, newController)
	require.NoError(err)

	newWorker := &servers.Server{
		PrivateId: "test-worker-new",
		Type:      "worker",
		Address:   "127.0.0.1",
		Tags: map[string]*servers.TagValues{
			"tag": {
				Values: []string{"value1", "value2"},
			},
		},
	}
	_, _, err = repo.UpsertServer(ctx, newWorker, servers.WithUpdateTags(true))
	require.NoError(err)

	// Assert length
	expectedControllers, err = repo.ListServers(ctx, servers.ServerTypeController)
	require.NoError(err)
	require.Len(expectedControllers, 2)

	expectedWorkers, err = repo.ListServers(ctx, servers.ServerTypeWorker)
	require.NoError(err)
	require.Len(expectedWorkers, 2)
}
