-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  create table target_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index target_deleted_time_idx on target_deleted (delete_time);

  create table session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index session_deleted_time_idx on session_deleted (delete_time);

  create table auth_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index auth_method_deleted_time_idx on auth_method_deleted (delete_time);

  create table auth_token_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index auth_token_deleted_time_idx on auth_token_deleted (delete_time);

  create table credential_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index credential_library_deleted_time_idx on credential_library_deleted (delete_time);

  create table credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index credential_deleted_time_idx on credential_deleted (delete_time);

  create table credential_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index credential_store_deleted_time_idx on credential_store_deleted (delete_time);

  create table iam_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index iam_group_deleted_time_idx on iam_group_deleted (delete_time);

  create table host_catalog_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index host_catalog_deleted_time_idx on host_catalog_deleted (delete_time);

  create table host_set_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index host_set_deleted_time_idx on host_set_deleted (delete_time);

  create table host_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index host_deleted_time_idx on host_deleted (delete_time);

  create table iam_role_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index iam_role_deleted_time_idx on iam_role_deleted (delete_time);

  create table iam_scope_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index iam_scope_deleted_time_idx on iam_scope_deleted (delete_time);

  create table storage_plugin_storage_bucket_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index storage_plugin_storage_bucket_deleted_time_idx on storage_plugin_storage_bucket_deleted (delete_time);

  create table iam_user_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index iam_user_deleted_time_idx on iam_user_deleted (delete_time);

  create table recording_session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index recording_session_deleted_time_idx on recording_session_deleted (delete_time);

  create table auth_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index auth_managed_group_deleted_time_idx on auth_managed_group_deleted (delete_time);

  create table server_worker_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index server_worker_deleted_time_idx on server_worker_deleted (delete_time);

  create table auth_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp
  );

  create index auth_account_deleted_time_idx on auth_account_deleted (delete_time);

  create table deletion_tables_enm (
    table_name text primary key
      constraint only_predefined_deletion_tables_allowed
      check (
        table_name in (
          'target_deleted',
          'session_deleted',
          'auth_method_deleted',
          'auth_token_deleted',
          'credential_library_deleted',
          'credential_deleted',
          'credential_store_deleted',
          'iam_group_deleted',
          'host_catalog_deleted',
          'host_set_deleted',
          'host_deleted',
          'iam_role_deleted',
          'iam_scope_deleted',
          'storage_plugin_storage_bucket_deleted',
          'iam_user_deleted',
          'recording_session_deleted',
          'auth_managed_group_deleted',
          'server_worker_deleted',
          'auth_account_deleted'
        )
      )
  );
  comment on table deletion_tables_enm is
    'deletion_tables_enm is an enumeration table for the names of tables that contain deleted entries.';

  insert into deletion_tables_enm (table_name)
  values
    ('target_deleted'),
    ('session_deleted'),
    ('auth_method_deleted'),
    ('auth_token_deleted'),
    ('credential_library_deleted'),
    ('credential_deleted'),
    ('credential_store_deleted'),
    ('iam_group_deleted'),
    ('host_catalog_deleted'),
    ('host_set_deleted'),
    ('host_deleted'),
    ('iam_role_deleted'),
    ('iam_scope_deleted'),
    ('storage_plugin_storage_bucket_deleted'),
    ('iam_user_deleted'),
    ('recording_session_deleted'),
    ('auth_managed_group_deleted'),
    ('server_worker_deleted'),
    ('auth_account_deleted');

  create or replace function insert_deleted_id() returns trigger
  as $$
  begin
    execute format('INSERT INTO %I (public_id, delete_time) values ($1, now())', tg_argv[0]) using old.public_id;
    return old;
  end;
  $$ language plpgsql;

  create trigger trigger_insert_deleted_target before delete on target
    for each row execute function insert_deleted_id('target_deleted');
  create trigger trigger_insert_deleted_session before delete on session
    for each row execute function insert_deleted_id('session_deleted');
  create trigger trigger_insert_deleted_auth_method before delete on auth_method
    for each row execute function insert_deleted_id('auth_method_deleted');
  create trigger trigger_insert_deleted_auth_token before delete on auth_token
    for each row execute function insert_deleted_id('auth_token_deleted');
  create trigger trigger_insert_deleted_credential_library before delete on credential_library
    for each row execute function insert_deleted_id('credential_library_deleted');
  create trigger trigger_insert_deleted_credential before delete on credential
    for each row execute function insert_deleted_id('credential_deleted');
  create trigger trigger_insert_deleted_credential_store before delete on credential_store
    for each row execute function insert_deleted_id('credential_store_deleted');
  create trigger trigger_insert_deleted_iam_group before delete on iam_group
    for each row execute function insert_deleted_id('iam_group_deleted');
  create trigger trigger_insert_deleted_host_catalog before delete on host_catalog
    for each row execute function insert_deleted_id('host_catalog_deleted');
  create trigger trigger_insert_deleted_host_set before delete on host_set
    for each row execute function insert_deleted_id('host_set_deleted');
  create trigger trigger_insert_deleted_host before delete on host
    for each row execute function insert_deleted_id('host_deleted');
  create trigger trigger_insert_deleted_iam_role before delete on iam_role
    for each row execute function insert_deleted_id('iam_role_deleted');
  create trigger trigger_insert_deleted_iam_scope before delete on iam_scope
    for each row execute function insert_deleted_id('iam_scope_deleted');
  create trigger trigger_insert_deleted_storage_plugin_storage_bucket before delete on storage_plugin_storage_bucket
    for each row execute function insert_deleted_id('storage_plugin_storage_bucket_deleted');
  create trigger trigger_insert_deleted_iam_user before delete on iam_user
    for each row execute function insert_deleted_id('iam_user_deleted');
  create trigger trigger_insert_deleted_recording_session before delete on recording_session
    for each row execute function insert_deleted_id('recording_session_deleted');
  create trigger trigger_insert_deleted_auth_managed_group before delete on auth_managed_group
    for each row execute function insert_deleted_id('auth_managed_group_deleted');
  create trigger trigger_insert_deleted_server_worker before delete on server_worker
    for each row execute function insert_deleted_id('server_worker_deleted');
  create trigger trigger_insert_deleted_auth_account before delete on auth_account
    for each row execute function insert_deleted_id('auth_account_deleted');
  
  create or replace function cleanup_deleted_tables() returns void
  as $$
  declare
    deletion_table_name TEXT;
  begin
    for deletion_table_name in select table_name from deletion_tables_enm loop
      execute 'delete from ' || quote_ident(deletion_table_name) || ' where delete_time < now() - interval ''30 days''';
    end loop;
  end;
  $$ language plpgsql;
commit;
