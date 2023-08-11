-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create table target_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_token_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table iam_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table host_catalog_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table host_set_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table host_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table iam_role_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table iam_scope_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table storage_plugin_storage_bucket_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table iam_user_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table recording_session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table server_worker_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create or replace function insert_deleted_id() returns trigger
  as $$
  begin
    execute format('insert into %I (public_id, delete_time) values ($1, now())', tg_argv[0]) using old.public_id;
    return old;
  end;
  $$ language plpgsql;

  create function get_deletion_tables() returns setof name
  as $$
    select c.relname
      from pg_catalog.pg_class c
     where c.relkind in ('r')
       and c.relname operator(pg_catalog.~) '^(.+_deleted)$' collate pg_catalog.default
       and pg_catalog.pg_table_is_visible(c.oid);
  $$ language sql;

  do $$
  declare
    deletion_table_name text;
    table_name          text;
  begin
    for deletion_table_name in select get_deletion_tables() loop
      table_name := split_part(deletion_table_name, '_deleted', 1);
      execute format('create trigger trigger_insert_on_deletion before delete on %I for each row execute function insert_deleted_id(''%I'')', table_name, deletion_table_name);
      execute format('create index %I_delete_time_idx on %I (delete_time)', deletion_table_name, deletion_table_name);
    end loop;
  end;
  $$ language plpgsql;
commit;
