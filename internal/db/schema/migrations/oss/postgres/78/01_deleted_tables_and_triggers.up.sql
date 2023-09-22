-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create table target_tcp_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table target_ssh_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Target repository list logic is implemented
  -- against views, so use a view for the deleted
  -- ids too.
  -- Note: does not end in _deleted so as
  -- not to be attached a trigger in the below function.
  create view target_all_subtypes_deleted_view
  as
    select * from target_tcp_deleted
    union
    select * from target_ssh_deleted;

  -- Sessions
  create table session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Auth methods
  create table auth_oidc_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_ldap_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_password_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Auth tokens
  create table auth_token_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Auth accounts
  create table auth_oidc_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_ldap_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_password_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Auth managed groups
  create table auth_oidc_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table auth_ldap_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Credential libraries
  create table credential_vault_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_vault_ssh_cert_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Credentials
  create table credential_static_json_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_static_username_password_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_static_ssh_private_key_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Credential stores
  create table credential_vault_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create table credential_static_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Groups
  create table iam_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Roles
  create table iam_role_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Scopes
  create table iam_scope_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Users
  create table iam_user_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Host catalogs
  create table host_plugin_catalog_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Host sets
  create table host_plugin_set_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Hosts
  create table host_plugin_host_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Storage buckets
  create table storage_plugin_storage_bucket_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Session recordings
  create table recording_session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  -- Workers
  create table server_worker_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );

  create or replace function insert_deleted_id() returns trigger
  as $$
  begin
    execute format('insert into %I (public_id, delete_time) values ($1, now()) on conflict (public_id) do update set delete_time = excluded.delete_time', tg_argv[0]) using old.public_id;
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

  -- These credential indices end up truncated by postgres, so we manually
  -- rename them to something nicer.
  alter index credential_static_username_password_credential_deleted_delete_t rename to credential_static_username_password_deleted_delete_time_idx;
  alter index credential_static_ssh_private_key_credential_deleted_delete_tim rename to credential_static_ssh_private_key_deleted_delete_time_idx;
commit;
