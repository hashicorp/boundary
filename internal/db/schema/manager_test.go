package schema

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/postgres"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	dialect := "postgres"
	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := sql.Open(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = NewManager(ctx, dialect, d)
	require.NoError(t, err)
	_, err = NewManager(ctx, "unknown", d)
	assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))

	d.Close()
	_, err = NewManager(ctx, dialect, d)
	assert.True(t, errors.Match(errors.T(errors.Op("schema.NewManager")), err))
}

func TestCurrentState(t *testing.T) {
	dialect := "postgres"
	c, u, _, err := docker.StartDbInDocker(dialect)
	t.Cleanup(func() {
		if err := c(); err != nil {
			t.Fatalf("Got error at cleanup: %v", err)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.Background()
	d, err := sql.Open(dialect, u)
	require.NoError(t, err)

	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	want := &State{
		BinarySchemaVersion:   BinarySchemaVersion(dialect),
		DatabaseSchemaVersion: nilVersion,
	}
	s, err := m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)

	testDriver, err := postgres.New(ctx, d)
	require.NoError(t, err)
	require.NoError(t, testDriver.SetVersion(ctx, 2, true))

	want = &State{
		InitializationStarted: true,
		BinarySchemaVersion:   BinarySchemaVersion(dialect),
		Dirty:                 true,
		DatabaseSchemaVersion: 2,
	}
	s, err = m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)
}

func TestRollForward(t *testing.T) {
	dialect := "postgres"
	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := sql.Open(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	// Now set to dirty at an early version
	testDriver, err := postgres.New(ctx, d)
	require.NoError(t, err)
	testDriver.SetVersion(ctx, 0, true)
	assert.Error(t, m.RollForward(ctx))
}

func TestRollForward_NotFromFresh(t *testing.T) {
	dialect := "postgres"
	oState := migrationStates[dialect]

	nState := createPartialMigrationState(oState, 8)
	migrationStates[dialect] = nState

	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := sql.Open(dialect, u)
	require.NoError(t, err)

	// Initialize the DB with only a portion of the current sql scripts.
	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.NoError(t, m.RollForward(ctx))

	ver, dirty, err := m.driver.CurrentState(ctx)
	assert.NoError(t, err)
	assert.Equal(t, nState.binarySchemaVersion, ver)
	assert.False(t, dirty)

	// Restore the full set of sql scripts and roll the rest of the way forward.
	migrationStates[dialect] = oState

	newM, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.NoError(t, newM.RollForward(ctx))
	ver, dirty, err = newM.driver.CurrentState(ctx)
	assert.NoError(t, err)
	assert.Equal(t, oState.binarySchemaVersion, ver)
	assert.False(t, dirty)
}

func TestManager_ExclusiveLock(t *testing.T) {
	ctx := context.Background()
	dialect := "postgres"
	c, u, _, err := docker.StartDbInDocker(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d1, err := sql.Open(dialect, u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, dialect, d1)
	require.NoError(t, err)

	d2, err := sql.Open(dialect, u)
	require.NoError(t, err)
	m2, err := NewManager(ctx, dialect, d2)
	require.NoError(t, err)

	assert.NoError(t, m1.ExclusiveLock(ctx))
	assert.NoError(t, m1.ExclusiveLock(ctx))
	assert.Error(t, m2.ExclusiveLock(ctx))
	assert.Error(t, m2.SharedLock(ctx))
}

func TestManager_SharedLock(t *testing.T) {
	ctx := context.Background()
	c, u, _, err := docker.StartDbInDocker("postgres")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d1, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := sql.Open("postgres", u)
	require.NoError(t, err)
	m2, err := NewManager(ctx, "postgres", d2)
	require.NoError(t, err)

	assert.NoError(t, m1.SharedLock(ctx))
	assert.NoError(t, m2.SharedLock(ctx))
	assert.NoError(t, m1.SharedLock(ctx))
	assert.NoError(t, m2.SharedLock(ctx))

	assert.Error(t, m1.ExclusiveLock(ctx))
	assert.Error(t, m2.ExclusiveLock(ctx))
}

// Creates a new migrationState only with the versions <= the provided maxVer
func createPartialMigrationState(om migrationState, maxVer int) migrationState {
	nState := migrationState{
		devMigration: om.devMigration,
		upMigrations: make(map[int][]byte),
	}
	for k := range om.upMigrations {
		if k > maxVer {
			// Don't store any versions past our test version.
			continue
		}
		nState.upMigrations[k] = om.upMigrations[k]
		if nState.binarySchemaVersion < k {
			nState.binarySchemaVersion = k
		}
	}
	return nState
}
