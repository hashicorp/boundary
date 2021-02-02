package schema

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateStore(t *testing.T) {
	dialect := "postgres"
	ctx := context.Background()

	c, u, _, err := docker.StartDbInDocker(dialect)
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
