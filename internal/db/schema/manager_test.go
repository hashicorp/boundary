package schema_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/migrations"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollForward(t *testing.T) {
	c, u, _, err := db.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := sql.Open("postgres", u)
	require.NoError(t, err)

	ctx := context.TODO()
	m, err := schema.NewManager(ctx, "postgres", d)
	require.NoError(t, err)
	s, err := m.State(ctx)
	require.NoError(t, err)

	want := &schema.State{
		BinarySchemaVersion: migrations.BinarySchemaVersion,
	}
	assert.Equal(t, want, s)

	assert.NoError(t, m.RollForward(ctx))

	s, err = m.State(ctx)
	require.NoError(t, err)
	want = &schema.State{
		InitializationStarted: true,
		CurrentSchemaVersion:  migrations.BinarySchemaVersion,
		BinarySchemaVersion:   migrations.BinarySchemaVersion,
	}
	assert.Equal(t, want, s)
}

func TestManager_ExclusiveLock(t *testing.T) {
	c, u, _, err := db.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.TODO()
	d1, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m1, err := schema.NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m2, err := schema.NewManager(ctx, "postgres", d2)
	require.NoError(t, err)

	assert.NoError(t, m1.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.SharedLock(ctx, 123))
}

func TestManager_SharedLock(t *testing.T) {
	c, u, _, err := db.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.TODO()
	d1, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m1, err := schema.NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m2, err := schema.NewManager(ctx, "postgres", d2)
	require.NoError(t, err)

	assert.NoError(t, m1.SharedLock(ctx, 123))
	assert.NoError(t, m2.SharedLock(ctx, 123))
	assert.NoError(t, m1.SharedLock(ctx, 123))
	assert.NoError(t, m2.SharedLock(ctx, 123))

	assert.Error(t, m1.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.ExclusiveLock(ctx, 123))
}
