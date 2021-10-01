package schema

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema/postgres"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
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
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	t.Cleanup(func() {
		if err := c(); err != nil {
			t.Fatalf("Got error at cleanup: %v", err)
		}
	})
	require.NoError(t, err)
	ctx := context.Background()
	d, err := common.SqlOpen(dialect, u)
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
	require.NoError(t, testDriver.EnsureVersionTable(ctx))
	require.NoError(t, testDriver.Run(ctx, strings.NewReader("select 1"), 2))

	want = &State{
		InitializationStarted: true,
		BinarySchemaVersion:   BinarySchemaVersion(dialect),
		DatabaseSchemaVersion: 2,
	}
	s, err = m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)
}

func TestRollForward(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.NoError(t, m.RollForward(ctx))

	// Now set to dirty at an early version
	_, err = postgres.New(ctx, d)
	require.NoError(t, err)
	// TODO: Extract out a way to mock the db to test failing rollforwards.
	_, err = d.ExecContext(ctx, "TRUNCATE boundary_schema_version; INSERT INTO boundary_schema_version (version, dirty) VALUES (2, true)")
	require.NoError(t, err)
	assert.Error(t, m.RollForward(ctx))
}

func TestRollForward_NotFromFresh(t *testing.T) {
	dialect := dbtest.Postgres
	oState := migrationStates[dialect]

	nState := createPartialMigrationState(oState, 8)
	migrationStates[dialect] = nState

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// Initialize the DB with only a portion of the current sql scripts.
	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.NoError(t, m.RollForward(ctx))

	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, nState.binarySchemaVersion, state.DatabaseSchemaVersion)
	assert.False(t, state.Dirty)

	// Restore the full set of sql scripts and roll the rest of the way forward.
	migrationStates[dialect] = oState

	newM, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.NoError(t, newM.RollForward(ctx))
	state, err = newM.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, oState.binarySchemaVersion, state.DatabaseSchemaVersion)
	assert.False(t, state.Dirty)
}

func TestRunMigration_canceledContext(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)

	// TODO: Find a way to test different parts of the runMigrations loop.
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	assert.Error(t, m.runMigrations(ctx, newStatementProvider(dialect, 0)))
}

func TestRollForward_BadSQL(t *testing.T) {
	dialect := dbtest.Postgres
	oState := migrationStates[dialect]
	defer func() { migrationStates[dialect] = oState }()

	nState := createPartialMigrationState(oState, 8)
	nState.binarySchemaVersion = 10
	nState.upMigrations[10] = []byte("SELECT 1 FROM NonExistantTable;")
	migrationStates[dialect] = nState

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// Initialize the DB with only a portion of the current sql scripts.
	ctx := context.Background()
	m, err := NewManager(ctx, dialect, d)
	require.NoError(t, err)
	assert.Error(t, m.RollForward(ctx))

	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, nilVersion, state.DatabaseSchemaVersion)
	assert.False(t, state.Dirty)
}

func TestManager_ExclusiveLock(t *testing.T) {
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d1, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, dialect, d1)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dialect, u)
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
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d1, err := common.SqlOpen("postgres", u)
	require.NoError(t, err)
	m1, err := NewManager(ctx, "postgres", d1)
	require.NoError(t, err)

	d2, err := common.SqlOpen("postgres", u)
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

func Test_GetMigrationLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen("postgres", u)
	require.NoError(t, err)
	m, err := NewManager(ctx, "postgres", d)
	require.NoError(t, err)
	require.NoError(t, m.RollForward(ctx))

	const insert = `insert into log_migration(entry) values ($1)`
	createEntries := func(entries ...string) {
		for _, e := range entries {
			_, err := d.Exec(insert, e)
			require.NoError(t, err)
		}
	}
	tests := []struct {
		name          string
		d             *sql.DB
		setup         func()
		withDeleteLog bool
		wantEntries   []string
		wantErrMatch  *errors.Template
	}{
		{
			name:        "simple",
			d:           d,
			setup:       func() { createEntries("alice", "eve", "bob") },
			wantEntries: []string{"alice", "eve", "bob"},
		},
		{
			name:          "with-delete-log",
			d:             d,
			setup:         func() { createEntries("alice", "eve", "bob") },
			withDeleteLog: true,
			wantEntries:   []string{"alice", "eve", "bob"},
		},
		{
			name:         "missing-sql-DB",
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// start with no log entries
			_, err := d.ExecContext(ctx, "truncate log_migration")
			require.NoError(err)

			if tt.setup != nil {
				tt.setup()
			}
			gotLog, err := GetMigrationLog(ctx, tt.d, WithDeleteLog(tt.withDeleteLog))
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "expected error with code: %s and got err: %q", tt.wantErrMatch.Code, err)
				return
			}
			require.NoError(err)
			var got []string
			for _, e := range gotLog {
				got = append(got, e.Entry)
			}
			sort.Strings(got)
			sort.Strings(tt.wantEntries)
			assert.Equal(tt.wantEntries, got)

			row := d.QueryRowContext(ctx, "select count(*) from log_migration")
			require.NoError(row.Err())
			var cnt int
			require.NoError(row.Scan(&cnt))
			if tt.withDeleteLog {
				assert.Equal(0, cnt)
			} else {
				assert.Equal(len(gotLog), cnt)
			}
		})
	}
}

// Creates a new migrationState only with the versions <= the provided maxVer
func createPartialMigrationState(om migrationState, maxVer int) migrationState {
	nState := migrationState{
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
