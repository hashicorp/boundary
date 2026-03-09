-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create table target_tcp_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table target_tcp_deleted is
    'target_tcp_deleted holds the ID and delete_time of every deleted TCP target. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table target_ssh_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table target_ssh_deleted is
    'target_ssh_deleted holds the ID and delete_time of every deleted SSH target. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Target repository list logic is implemented
  -- against views, so use a view for the deleted
  -- ids too.
  -- Note: does not end in _deleted so as
  -- not to be attached a trigger in the below function.
  -- replaced in 98/04_rdp_targets.up.sql
  create view target_all_subtypes_deleted_view
  as
    select public_id, delete_time from target_tcp_deleted
    union
    select public_id, delete_time from target_ssh_deleted;
  comment on view target_all_subtypes_deleted_view is
    'target_all_subtypes_deleted_view holds the ID and delete_time of every deleted target.';

  -- Sessions
  create table session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table session_deleted is
    'session_deleted holds the ID and delete_time of every deleted session. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Auth methods
  create table auth_oidc_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_oidc_method_deleted is
    'auth_oidc_method_deleted holds the ID and delete_time of every deleted OIDC auth method. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table auth_ldap_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_ldap_method_deleted is
    'auth_ldap_method_deleted holds the ID and delete_time of every deleted LDAP auth method. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table auth_password_method_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_password_method_deleted is
    'auth_password_method_deleted holds the ID and delete_time of every deleted password auth method. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Auth tokens
  create table auth_token_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_token_deleted is
    'auth_token_deleted holds the ID and delete_time of every deleted auth token. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Auth accounts
  create table auth_oidc_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_oidc_account_deleted is
    'auth_oidc_account_deleted holds the ID and delete_time of every deleted OIDC account. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table auth_ldap_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_ldap_account_deleted is
    'auth_ldap_account_deleted holds the ID and delete_time of every deleted LDAP account. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table auth_password_account_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_password_account_deleted is
    'auth_password_account_deleted holds the ID and delete_time of every deleted password account. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Auth managed groups
  create table auth_oidc_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_oidc_managed_group_deleted is
    'auth_oidc_managed_group_deleted holds the ID and delete_time of every deleted OIDC managed group. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table auth_ldap_managed_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table auth_ldap_managed_group_deleted is
    'auth_ldap_managed_group_deleted holds the ID and delete_time of every deleted LDAP managed group. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Credential libraries
  -- Renamed in 99/01_credential_vault_library_refactor.up.sql
  create table credential_vault_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_vault_library_deleted is
    'credential_vault_library_deleted holds the ID and delete_time of every deleted Vault credential library. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table credential_vault_ssh_cert_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_vault_ssh_cert_library_deleted is
    'credential_vault_ssh_cert_library_deleted holds the ID and delete_time of '
    'every deleted Vault SSH certificate credential library. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Credentials
  create table credential_static_json_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_static_json_credential_deleted is
    'credential_static_json_credential_deleted holds the ID and delete_time '
    'of every deleted static JSON credential. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table credential_static_username_password_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_static_username_password_credential_deleted is
    'credential_static_username_password_credential_deleted holds the ID and delete_time '
    'of every deleted static username password credential. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table credential_static_ssh_private_key_credential_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_static_ssh_private_key_credential_deleted is
    'credential_static_ssh_private_key_credential_deleted holds the ID and delete_time '
    'of every deleted static ssh private key credential. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Credential stores
  create table credential_vault_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_vault_store_deleted is
    'credential_vault_store_deleted holds the ID and delete_time '
    'of every deleted Vault credential store. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table credential_static_store_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_static_store_deleted is
    'credential_static_store_deleted holds the ID and delete_time '
    'of every deleted static credential store. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Groups
  create table iam_group_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table iam_group_deleted is
    'iam_group_deleted holds the ID and delete_time of every deleted group. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Roles
  create table iam_role_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table iam_role_deleted is
    'iam_role_deleted holds the ID and delete_time of every deleted role. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Scopes
  create table iam_scope_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table iam_scope_deleted is
    'iam_scope_deleted holds the ID and delete_time of every deleted scope. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Users
  create table iam_user_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table iam_user_deleted is
    'iam_user_deleted holds the ID and delete_time of every deleted user. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Host catalogs
  create table host_plugin_catalog_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table host_plugin_catalog_deleted is
    'host_plugin_catalog_deleted holds the ID and delete_time of every deleted plugin host catalog. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table static_host_catalog_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table static_host_catalog_deleted is
    'static_host_catalog_deleted holds the ID and delete_time of every deleted static host catalog. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Host sets
  create table host_plugin_set_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table host_plugin_set_deleted is
    'host_plugin_set_deleted holds the ID and delete_time of every deleted plugin host set. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table static_host_set_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table static_host_set_deleted is
    'static_host_set_deleted holds the ID and delete_time of every deleted static host set. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Hosts
  create table host_plugin_host_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table host_plugin_host_deleted is
    'host_plugin_host_deleted holds the ID and delete_time of every deleted plugin host. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create table static_host_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table static_host_deleted is
    'static_host_deleted holds the ID and delete_time of every deleted static host. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Storage buckets
  create table storage_plugin_storage_bucket_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table storage_plugin_storage_bucket_deleted is
    'storage_plugin_storage_bucket_deleted holds the ID and delete_time of every deleted storage bucket. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Session recordings
  create table recording_session_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table recording_session_deleted is
    'recording_session_deleted holds the ID and delete_time of every deleted session recording. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Workers
  create table server_worker_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table server_worker_deleted is
    'server_worker_deleted holds the ID and delete_time of every deleted worker. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create function insert_deleted_id() returns trigger
  as $$
  begin
    execute format('insert into %I (public_id, delete_time) values ($1, now()) on conflict (public_id) do update set delete_time = excluded.delete_time', tg_argv[0]) using old.public_id;
    return old;
  end;
  $$ language plpgsql;
  comment on function insert_deleted_id is
    'insert_deleted_id is a function that inserts a record into the table '
    'specified by the first trigger argument. It takes the public ID from the row '
    'affected by the trigger and the current timestamp. It is used to populate rows '
    'of the deleted tables.';

  -- Removed in 91/05_deletion_tables_view and replaced with a view.
  create function get_deletion_tables() returns setof name
  as $$
    select c.relname
      from pg_catalog.pg_class c
     where c.relkind in ('r')
       and c.relname operator(pg_catalog.~) '^(.+_deleted)$' collate pg_catalog.default
       and pg_catalog.pg_table_is_visible(c.oid);
  $$ language sql;
  comment on function get_deletion_tables is
    'get_deletion_tables returns a set containing all the deleted table names by looking for '
    'all tables that end in _deleted.';

  -- Assign a "after delete" trigger on all deleted tables to run insert_deleted_id
  do $$
  declare
    deletion_table_name text;
    table_name          text;
  begin
    for deletion_table_name in select get_deletion_tables() loop
      table_name := split_part(deletion_table_name, '_deleted', 1);
      execute format('create trigger insert_deleted_id after delete on %I for each row execute function insert_deleted_id(''%I'')', table_name, deletion_table_name);
      execute format('create index %I_delete_time_idx on %I (delete_time)', deletion_table_name, deletion_table_name);
    end loop;
  end;
  $$ language plpgsql;

  -- These credential indices end up truncated by postgres, so we manually
  -- rename them to something nicer.
  alter index credential_static_username_password_credential_deleted_delete_t rename to credential_static_username_password_deleted_delete_time_idx;
  alter index credential_static_ssh_private_key_credential_deleted_delete_tim rename to credential_static_ssh_private_key_deleted_delete_time_idx;
commit;
