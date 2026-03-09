// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema_test

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"

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
				Migrations: migration.Migrations{
					2: migration.Migration{
						Statements: []byte(`select 1`),
						Edition:    "oss",
						Version:    2,
					},
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

	_, err = m.ApplyMigrations(ctx)
	assert.NoError(t, err)

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
				func() edition.Edition {
					e, _ := edition.New("one", schema.Postgres, one, 0)
					return e
				}(),
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
				func() edition.Edition {
					e, _ := edition.New("one", schema.Postgres, one, 0)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("two", schema.Postgres, two, 1)
					return e
				}(),
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
				func() edition.Edition {
					e, _ := edition.New("one", schema.Postgres, one, 1)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("two", schema.Postgres, two, 0)
					return e
				}(),
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
				func() edition.Edition {
					e, _ := edition.New("one", schema.Postgres, one, 0)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("two", schema.Postgres, two, 1)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("three", schema.Postgres, three, 2)
					return e
				}(),
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
				func() edition.Edition {
					e, _ := edition.New("one", schema.Postgres, one, 0)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("two", schema.Postgres, two, 2)
					return e
				}(),
				func() edition.Edition {
					e, _ := edition.New("three", schema.Postgres, three, 1)
					return e
				}(),
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
				_, err = m.ApplyMigrations(ctx)
				assert.Error(t, err)
			} else {
				_, err = m.ApplyMigrations(ctx)
				assert.NoError(t, err)
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

func TestApplyMigrationWithHooks(t *testing.T) {
	tests := []struct {
		name       string
		editions   edition.Editions
		repairs    schema.RepairMigrations
		expectErr  error
		state      *schema.State
		repairLogs []schema.RepairLog
	}{
		{
			"checkPass",
			edition.Editions{
				func() edition.Edition {
					e, _ := edition.New(
						"hooks",
						schema.Postgres,
						hooksUpdated,
						0,
						edition.WithPreHooks(
							map[int]*migration.Hook{
								1001: {
									CheckFunc: func(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
										return nil, nil
									},
								},
							},
						),
					)
					return e
				}(),
			},
			nil,
			nil,
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "hooks",
						BinarySchemaVersion:   2001,
						DatabaseSchemaVersion: 2001,
						DatabaseSchemaState:   schema.Equal,
					},
				},
			},
			nil,
		},
		{
			"checkFailure",
			edition.Editions{
				func() edition.Edition {
					e, _ := edition.New(
						"hooks",
						schema.Postgres,
						hooksUpdated,
						0,
						edition.WithPreHooks(
							map[int]*migration.Hook{
								2001: {
									CheckFunc: func(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
										return migration.Problems{"failed"}, nil
									},
									RepairDescription: "repair all the things",
								},
							},
						),
					)
					return e
				}(),
			},
			nil,
			schema.MigrationCheckError{
				Version:           2001,
				Edition:           "hooks",
				Problems:          migration.Problems{"failed"},
				RepairDescription: "repair all the things",
			},
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "hooks",
						BinarySchemaVersion:   2001,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Behind,
					},
				},
			},
			nil,
		},
		{
			"repair",
			edition.Editions{
				func() edition.Edition {
					e, _ := edition.New(
						"hooks",
						schema.Postgres,
						hooksUpdated,
						0,
						edition.WithPreHooks(
							map[int]*migration.Hook{
								1001: {
									CheckFunc: func(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
										return migration.Problems{"failed"}, nil
									},
									RepairFunc: func(ctx context.Context, tx *sql.Tx) (migration.Repairs, error) {
										return migration.Repairs{"repaired all the things"}, nil
									},
								},
							},
						),
					)
					return e
				}(),
			},
			schema.RepairMigrations{
				"hooks": map[int]bool{
					1001: true,
				},
			},
			nil,
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "hooks",
						BinarySchemaVersion:   2001,
						DatabaseSchemaVersion: 2001,
						DatabaseSchemaState:   schema.Equal,
					},
				},
			},
			[]schema.RepairLog{
				{
					Edition: "hooks",
					Version: 1001,
					Entry:   migration.Repairs{"repaired all the things"},
				},
			},
		},
		{
			"repairRequestNoRepairFunc",
			edition.Editions{
				func() edition.Edition {
					e, _ := edition.New(
						"hooks",
						schema.Postgres,
						hooksUpdated,
						0,
						edition.WithPreHooks(
							map[int]*migration.Hook{
								1001: {
									CheckFunc: func(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
										return migration.Problems{"failed"}, nil
									},
								},
							},
						),
					)
					return e
				}(),
			},
			schema.RepairMigrations{
				"hooks": map[int]bool{
					1001: true,
				},
			},
			fmt.Errorf("schema.(Manager).runMigrations: postgres.(Postgres).RepairHook: no repair function: integrity violation: error #2000"),
			&schema.State{
				Initialized: true,
				Editions: []schema.EditionState{
					{
						Name:                  "hooks",
						BinarySchemaVersion:   2001,
						DatabaseSchemaVersion: 1,
						DatabaseSchemaState:   schema.Behind,
					},
				},
			},
			nil,
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

			m, err := schema.NewManager(
				ctx,
				schema.Dialect(dialect),
				d,
				schema.WithEditions(
					edition.Editions{
						func() edition.Edition {
							e, _ := edition.New(
								"hooks",
								schema.Postgres,
								hooksInitial,
								0,
							)
							return e
						}(),
					},
				),
			)
			require.NoError(t, err)
			logs, err := m.ApplyMigrations(ctx)
			assert.NoError(t, err)
			assert.Empty(t, logs)

			m, err = schema.NewManager(
				ctx,
				schema.Dialect(dialect),
				d,
				schema.WithEditions(tt.editions),
				schema.WithRepairMigrations(tt.repairs),
			)
			require.NoError(t, err)

			logs, err = m.ApplyMigrations(ctx)
			if tt.expectErr != nil {
				assert.EqualError(t, tt.expectErr, err.Error())
				if want, ok := tt.expectErr.(schema.MigrationCheckError); ok {
					got, ok := err.(schema.MigrationCheckError)
					assert.True(t, ok, "not a schema.MigrationCheckError")
					assert.Equal(t, want, got)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.ElementsMatch(t, tt.repairLogs, logs)

			s, err := m.CurrentState(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.state.Initialized, s.Initialized)
			assert.ElementsMatch(t, tt.state.Editions, s.Editions)

			if tt.expectErr != nil {
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
	_, err = m.ApplyMigrations(ctx)
	assert.Error(t, err)
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
				Migrations: migration.Migrations{
					2: migration.Migration{
						Statements: []byte(`select 1 from nonexistenttable;`),
						Edition:    "oss",
						Version:    2,
					},
				},
				Priority: 0,
			},
		},
	))
	require.NoError(t, err)
	_, err = m.ApplyMigrations(ctx)
	assert.Error(t, err)

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
	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)

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
