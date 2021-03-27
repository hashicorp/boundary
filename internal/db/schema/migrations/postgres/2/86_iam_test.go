package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrimaryAuthMethodChanges(t *testing.T) {
	const primaryAuthMethodMigration = 2086
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	dialect := "postgres"
	ctx := context.Background()

	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	oState := schema.TestCloneMigrationStates(t)
	nState := schema.TestCreatePartialMigrationState(oState["postgres"], primaryAuthMethodMigration)
	oState["postgres"] = nState

	d, err := sql.Open(dialect, u)
	require.NoError(err)

	ok, err := schema.MigrateStore(ctx, "postgres", u, schema.WithMigrationStates(oState))
	require.NoError(err)
	require.True(ok)

	m, err := schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	state, err := m.CurrentState(ctx)
	require.NoError(err)
	assert.Equal(primaryAuthMethodMigration, state.DatabaseSchemaVersion)
	assert.False(state.Dirty)

	assert.NoError(m.RollForward(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(err)
	assert.Equal(primaryAuthMethodMigration, state.DatabaseSchemaVersion)
	assert.False(state.Dirty)
}
