package schema

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollForward(t *testing.T) {
	c, u, _, err := docker.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := sql.Open("postgres", u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := NewManager(ctx, "postgres", d)
	require.NoError(t, err)
	assert.NoError(t, m.RollForward(ctx))

	// Now set to dirty at an early version
	testDriver, err := newPostgres(ctx, d)
	require.NoError(t, err)
	testDriver.setVersion(ctx, 0, true)
	assert.Error(t, m.RollForward(ctx))
}

func TestManager_ExclusiveLock(t *testing.T) {
	c, u, _, err := docker.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.TODO()
	d1, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m2, err := NewManager(ctx, "postgres", d2)
	require.NoError(t, err)

	assert.NoError(t, m1.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.SharedLock(ctx, 123))
}

func TestManager_SharedLock(t *testing.T) {
	c, u, _, err := docker.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.TODO()
	d1, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m2, err := NewManager(ctx, "postgres", d2)
	require.NoError(t, err)

	assert.NoError(t, m1.SharedLock(ctx, 123))
	assert.NoError(t, m2.SharedLock(ctx, 123))
	assert.NoError(t, m1.SharedLock(ctx, 123))
	assert.NoError(t, m2.SharedLock(ctx, 123))

	assert.Error(t, m1.ExclusiveLock(ctx, 123))
	assert.Error(t, m2.ExclusiveLock(ctx, 123))
}
