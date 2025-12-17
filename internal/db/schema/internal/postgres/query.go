// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres

// Queries for interacting with locks
const (
	trySharedLock    = `select pg_try_advisory_lock_shared($1)`
	tryLock          = `select pg_try_advisory_lock($1)`
	lock             = `select pg_advisory_lock($1)`
	unlock           = `select pg_advisory_unlock($1)`
	unlockSharedLock = `select pg_advisory_unlock_shared($1)`
)

// Queries for interacting with the schema version table
const (
	schemaVersionTable = `boundary_schema_version`
	upsertVersion      = `
insert into boundary_schema_version
	(edition, version)
values
	($1, $2)
on conflict (edition)
do update set
	version = $2
;`

	selectVersion = `
select version
  from boundary_schema_version
 where edition = $1
;`

	selectOldVersion = `
select version from schema_migrations;
`

	selectPreEditionVersion = `
select max(version) from boundary_schema_version;
`

	tablesExist = `
select table_name from information_schema.tables
 where table_schema =  (select current_schema())
   and table_name   in ('schema_migrations', 'boundary_schema_version')
;`

	tableExists = `
select exists (
	select 1 from information_schema.tables
	 where table_schema = (select current_schema())
	   and table_name   = 'boundary_schema_version'
);`

	oldTableExists = `
select exists (
	select 1 from information_schema.tables
	 where table_schema = (select current_schema())
	   and table_name   = 'schema_migrations'
);`

	updateTableName = `
alter table if exists schema_migrations
	rename to boundary_schema_version
;`

	dropDirtyColumn = `
alter table boundary_schema_version
	drop column if exists dirty
;`

	addEditionColumn = `
alter table boundary_schema_version
	add column if not exists
	edition text default 'oss';
alter table boundary_schema_version
	alter column edition drop default;
alter table boundary_schema_version drop constraint if exists schema_migrations_pkey;
alter table boundary_schema_version drop constraint if exists boundary_schema_version_pkey;
alter table boundary_schema_version add primary key (edition);
`
	setVersionNotNull = `
alter table boundary_schema_version
	alter column version set not null;
`
)

// Quries for interacting with migration logs table
const (
	migrationLogTableExists = `
select exists (
	select 1 from information_schema.tables
	 where table_schema = (select current_schema())
	   and table_name   = 'log_migration'
);`

	getMigrationLogs = `
select
	id, create_time, migration_version, edition, entry
 from log_migration
where
  migration_version in (
    select max(version) from boundary_schema_version
  );`

	truncateMigrationLogs = `truncate log_migration;`

	migrationLogAlterColumns = `
alter table log_migration
	alter column create_time type timestamp with time zone;
alter table log_migration
	alter column create_time set default current_timestamp;
`
	migrationLogDropTriggers = `
drop trigger if exists default_create_time_column on log_migration;
drop trigger if exists immutable_columns on log_migration;
`
	migrationLogAddEditionColumn = `
alter table log_migration
	add column if not exists
	edition text default 'oss';
alter table log_migration
	alter column edition drop default;
`
	migrationLogReplaceVersionTrigger = `
create or replace function log_migration_version() returns trigger
as $$
  declare current_version bigint;
  begin
    select max(version)
	  from boundary_schema_version into current_version
	 where edition = new.edition;
    new.migration_version = current_version;
    return new;
  end;
$$ language plpgsql;
comment on function log_migration_version() is
  'log_migration_version will set the log_migration entries to the current migration version';
`
)
