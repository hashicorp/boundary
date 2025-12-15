// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureMigrationLog(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)

	err := p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.EnsureMigrationLogTable(ctx)
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)
}

func TestEnsureMigrationLog_NoTxn(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)
	err := p.EnsureMigrationLogTable(ctx)
	require.Error(t, err)
}

// Test that a database that was created with a log_migration table
// prior to edition support, can be updated to support editions,
// and any existing log entries can be updated.
//
// The scenario involves a case where:
// - The database was initialized with the original boundary_schema_version table
// - The original migrations where run, creating the log_migration table and some entries in the table.
func TestEnsureMigrationLog_UpdateForEditionSupport(t *testing.T) {
	ctx := context.Background()
	p, db, _ := setup(ctx, t)

	statements := []string{
		// original boundary_schema_version table
		`create table boundary_schema_version (
			 version bigint primary key,
			 dirty boolean not null);`,
		// populate the table with a version
		`insert into boundary_schema_version
			 (version, dirty)
		 values
			 (1001, false);`,
		// need to create some things from other migrations that the original tables used
		`create domain wt_timestamp as
			 timestamp with time zone
			 default current_timestamp;

			create or replace function default_create_time() returns trigger
			as $$
			begin
				if new.create_time is distinct from now() then
					raise warning 'create_time cannot be set to %', new.create_time;
					new.create_time = now();
				end if;
				return new;
			end;
			$$ language plpgsql;

			create or replace function immutable_columns() returns trigger
			as $$
			declare
				col_name text;
				new_value text;
				old_value text;
			begin
				foreach col_name in array tg_argv loop
					execute format('SELECT $1.%I', col_name) into new_value using new;
					execute format('SELECT $1.%I', col_name) into old_value using old;
					if new_value is distinct from old_value then
						raise exception 'immutable column: %.%', tg_table_name, col_name using
							errcode = '23601',
							schema = tg_table_schema,
							table = tg_table_name,
							column = col_name;
					end if;
				end loop;
				return new;
			end;
			$$ language plpgsql;
		`,
		// create original log_migration table, triggers
		`create table log_migration(
			id bigint generated always as identity primary key,
			migration_version bigint not null, -- cannot declare FK since the table is truncated during runtime
			create_time wt_timestamp,
			entry text not null
		 );
		 comment on table log_migration is
		   'log_migration entries are logging output from databaes migrations';

		 create trigger
			default_create_time_column
		 before
		 insert on log_migration
			for each row execute procedure default_create_time();

		 create trigger
			immutable_columns
		 before
		 update on log_migration
			for each row execute procedure immutable_columns('id', 'migration_version', 'create_time', 'entry');

		 create or replace function log_migration_version() returns trigger
		 as $$
			declare current_version bigint;
			begin
				select max(version) from boundary_schema_version into current_version;
				new.migration_version = current_version;
				return new;
			end;
		 $$ language plpgsql;
		 comment on function log_migration_version() is
		   'log_migration_version will set the log_migration entries to the current migration version';

		 create trigger
			migration_version_column
		 before
		 insert on log_migration
			for each row execute procedure log_migration_version();
		`,
		// insert some logs
		`insert into log_migration (entry)
		values
		 ('log entry');`,
	}

	for _, s := range statements {
		_, err := db.ExecContext(ctx, s)
		require.NoError(t, err)
	}

	err := p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.EnsureMigrationLogTable(ctx)
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)

	logs, err := p.GetMigrationLog(ctx, log.WithDeleteLog(true))
	require.NoError(t, err)
	assert.Equal(t, 1, len(logs))
	assert.NotEqual(t, logs[0].Id, 0)
	assert.False(t, logs[0].CreateTime.IsZero())
	assert.Equal(t, "oss", logs[0].MigrationEdition)
	assert.Equal(t, 1001, logs[0].MigrationVersion)
	assert.Equal(t, "log entry", logs[0].Entry)

	// now ensure the updated table and trigger still works
	statements = []string{
		// update the version, to make it easy to filter on log_migrations
		`update boundary_schema_version set version = 1002;`,
		// insert a new log entry
		`insert into log_migration (entry, edition)
		values
		 ('new log entry', 'oss');`,
	}
	for _, s := range statements {
		_, err := db.ExecContext(ctx, s)
		require.NoError(t, err)
	}

	logs, err = p.GetMigrationLog(ctx, log.WithDeleteLog(true))
	require.NoError(t, err)
	assert.Equal(t, 1, len(logs))
	assert.NotEqual(t, logs[0].Id, 0)
	assert.False(t, logs[0].CreateTime.IsZero())
	assert.Equal(t, "oss", logs[0].MigrationEdition)
	assert.Equal(t, 1002, logs[0].MigrationVersion)
	assert.Equal(t, "new log entry", logs[0].Entry)

	// ensure it is idempotent
	err = p.StartRun(ctx)
	require.NoError(t, err)
	err = p.EnsureMigrationLogTable(ctx)
	require.NoError(t, err)
	err = p.CommitRun(ctx)
	require.NoError(t, err)
}
