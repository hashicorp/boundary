package migration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

const targetMigration = 12001

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

	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := sql.Open(dialect, u)
	require.NoError(err)

	oState := schema.TestCloneMigrationStates(t)
	nState := schema.TestCreatePartialMigrationState(oState["postgres"], targetMigration)
	oState["postgres"] = nState

	m, err := schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	require.NoError(m.RollForward(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	require.Equal(targetMigration, state.DatabaseSchemaVersion)
	require.False(state.Dirty)

	return d
}
