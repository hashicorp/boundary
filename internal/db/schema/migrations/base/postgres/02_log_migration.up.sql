-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
create table log_migration(
  id                bigint generated always as identity primary key,
  migration_version bigint not null, -- cannot declare FK since the table is truncated during runtime
  edition           text   not null, -- cannot declare FK since the table is truncated during runtime
  create_time       timestamp with time zone default current_timestamp,
  entry             text   not null
);
comment on table log_migration is
  'log_migration entries are logging output from database migrations';

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

create trigger
  version_column
before
  insert on log_migration
  for each row execute procedure log_migration_version();

commit;
