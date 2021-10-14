package schema_test

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"

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
	_, err = schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	_, err = schema.NewManager(ctx, schema.Dialect("unknown"), d)
	assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))

	d.Close()
	_, err = schema.NewManager(ctx, schema.Dialect(dialect), d)
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

	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 2,
				Migrations: map[int][]byte{
					2: []byte(`select 1`),
				},
				Priority: 0,
			},
		},
	))
	require.NoError(t, err)
	want := &schema.State{
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   2,
				DatabaseSchemaVersion: schema.NilVersion,
				DatabaseSchemaState:   schema.Behind,
			},
		},
	}
	s, err := m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)

	assert.NoError(t, m.ApplyMigrations(ctx))

	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   2,
				DatabaseSchemaVersion: 2,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	s, err = m.CurrentState(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)
	assert.True(t, s.MigrationsApplied())
}

func TestApplyMigration(t *testing.T) {
	tests := []struct {
		name      string
		editions  edition.Editions
		expectErr bool
		state     *schema.State
	}{
		{
			"oneEdition",
			edition.Editions{
				edition.New("one", schema.Postgres, one, 0),
			},
			false,
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "one",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
				},
			},
		},
		{
			"twoEditions",
			edition.Editions{
				edition.New("one", schema.Postgres, one, 0),
				edition.New("two", schema.Postgres, two, 1),
			},
			false,
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "one",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
					{
						Name:                  "two",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
				},
			},
		},
		{
			"twoEditionsIncorrectPriority",
			edition.Editions{
				edition.New("one", schema.Postgres, one, 1),
				edition.New("two", schema.Postgres, two, 0),
			},
			true,
			&schema.State{
				Initialized: false,
				Editions: []schema.EditionState{
					{
						Name:                  "one",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: schema.NilVersion,
						DatabaseSchemaState:   schema.Behind,
					},
					{
						Name:                  "two",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: schema.NilVersion,
						DatabaseSchemaState:   schema.Behind,
					},
				},
			},
		},
		{
			"threeEditions",
			edition.Editions{
				edition.New("one", schema.Postgres, one, 0),
				edition.New("two", schema.Postgres, two, 1),
				edition.New("three", schema.Postgres, three, 2),
			},
			false,
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "one",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
					{
						Name:                  "two",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
					{
						Name:                  "three",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Equal,
					},
				},
			},
		},
		{
			"threeEditionsIncorrectPriority",
			edition.Editions{
				edition.New("one", schema.Postgres, one, 0),
				edition.New("two", schema.Postgres, two, 2),
				edition.New("three", schema.Postgres, three, 1),
			},
			true,
			&schema.State{
				Initialized: false,
				Editions: []schema.EditionState{
					{
						Name:                  "one",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: schema.NilVersion,
						DatabaseSchemaState:   schema.Behind,
					},
					{
						Name:                  "two",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: schema.NilVersion,
						DatabaseSchemaState:   schema.Behind,
					},
					{
						Name:                  "three",
						BinarySchemaVersion:   1,
						DatabaseSchemaVersion: schema.NilVersion,
						DatabaseSchemaState:   schema.Behind,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(tt.editions))
			require.NoError(t, err)
			if tt.expectErr {
				assert.Error(t, m.ApplyMigrations(ctx))
			} else {
				assert.NoError(t, m.ApplyMigrations(ctx))
			}

			s, err := m.CurrentState(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.state.Initialized, s.Initialized)
			assert.ElementsMatch(t, tt.state.Editions, s.Editions)

			if tt.expectErr {
				assert.False(t, s.MigrationsApplied())
			} else {
				assert.True(t, s.MigrationsApplied())
			}
		})
	}
}

func TestApplyMigration_canceledContext(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(ctx)
	cancel()
	assert.Error(t, m.ApplyMigrations(ctx))
}

func TestApplyMigrations_BadSQL(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// Initialize the DB with only a portion of the current sql scripts.
	ctx := context.Background()
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 1,
				Migrations: map[int][]byte{
					1: []byte(`select 1 from nonexistanttable;`),
				},
				Priority: 0,
			},
		},
	))
	require.NoError(t, err)
	assert.Error(t, m.ApplyMigrations(ctx))

	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	want := &schema.State{
		Initialized: false,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   1,
				DatabaseSchemaVersion: schema.NilVersion,
				DatabaseSchemaState:   schema.Behind,
			},
		},
	}
	assert.Equal(t, want, state)
	assert.False(t, state.MigrationsApplied())
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
	m1, err := schema.NewManager(ctx, schema.Dialect(dialect), d1)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)
	m2, err := schema.NewManager(ctx, schema.Dialect(dialect), d2)
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
	d1, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)
	m1, err := schema.NewManager(ctx, schema.Dialect(dialect), d1)
	require.NoError(t, err)

	d2, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)
	m2, err := schema.NewManager(ctx, schema.Dialect(dialect), d2)
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
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	require.NoError(t, m.ApplyMigrations(ctx))

	const insert = `insert into log_migration(entry, edition) values ($1, $2)`
	createEntries := func(entries ...string) {
		for _, e := range entries {
			_, err := d.Exec(insert, e, "oss")
			require.NoError(t, err)
		}
	}
	tests := []struct {
		name          string
		setup         func()
		withDeleteLog bool
		wantEntries   []string
		wantErrMatch  *errors.Template
	}{
		{
			name:        "simple",
			setup:       func() { createEntries("alice", "eve", "bob") },
			wantEntries: []string{"alice", "eve", "bob"},
		},
		{
			name:          "with-delete-log",
			setup:         func() { createEntries("alice", "eve", "bob") },
			withDeleteLog: true,
			wantEntries:   []string{"alice", "eve", "bob"},
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
			gotLog, err := m.GetMigrationLog(ctx, schema.WithDeleteLog(tt.withDeleteLog))
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
