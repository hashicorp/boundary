package schema

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateStore(t *testing.T) {
	dialect := dbtest.Postgres
	ctx := context.Background()

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})

	// Set the possible migration state to be only part of the full migration
	oState := migrationStates[dialect]
	nState := createPartialMigrationState(oState, 8)
	migrationStates[dialect] = nState

	ran, err := MigrateStore(ctx, dialect, u)
	assert.NoError(t, err)
	assert.True(t, ran)
	ran, err = MigrateStore(ctx, dialect, u)
	assert.NoError(t, err)
	assert.False(t, ran)

	// Reset the possible migration state to contain everything
	migrationStates[dialect] = oState

	ran, err = MigrateStore(ctx, dialect, u)
	assert.NoError(t, err)
	assert.True(t, ran)
	ran, err = MigrateStore(ctx, dialect, u)
	assert.NoError(t, err)
	assert.False(t, ran)
}

func Test_MigrateStore_WithMigrationStates(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
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
	oState := TestCloneMigrationStates(t)
	nState := TestCreatePartialMigrationState(oState["postgres"], 8)
	oState["postgres"] = nState

	ran, err := MigrateStore(ctx, dialect, u, WithMigrationStates(oState))
	assert.NoError(err)
	assert.True(ran)

	m, err := NewManager(ctx, dialect, d, WithMigrationStates(oState))
	require.NoError(err)
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	assert.Equal(8, state.DatabaseSchemaVersion)
	assert.False(state.Dirty)
}
