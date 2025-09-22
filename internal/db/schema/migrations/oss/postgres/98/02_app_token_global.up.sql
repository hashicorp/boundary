-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1
begin;

  -- Main app_token table similar to iam_role structure
  create table app_token_global (
    public_id wt_public_id primary key
      constraint app_token_fkey
        references app_token(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_global_scope_id_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    status text not null default 'active'
      constraint app_token_status_enm_fkey
        references app_token_status_enm(name)
        on delete restrict
        on update cascade,
    created_time wt_timestamp,
    updated_time wt_timestamp,
    created_by_user_hst_id wt_url_safe_id not null
      constraint app_token_created_by_fkey
        references iam_user_hst(history_id)
        on delete restrict
        on update cascade,
    approximate_last_access_time wt_timestamp
      constraint last_access_time_must_not_be_after_expiration_time
      check(
        approximate_last_access_time <= expiration_time
      ),
    time_to_stale_seconds integer not null default 0
      constraint time_to_stale_seconds_must_be_non_negative
        check(time_to_stale_seconds >= 0),
    expiration_time wt_timestamp
      constraint created_time_must_not_be_after_expiration_time
      check(
        created_time <= expiration_time
      ),
    key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    token bytea not null unique,
    version wt_version,
    constraint app_token_global_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table app_token_global is
    'app_token_global is the table for application tokens in global scope';

  -- Add index for querying app_token by created_by (user)
  create index app_token_global_created_by_idx on app_token_global (created_by_user_hst_id);
  
  -- Add triggers for app_token
  create trigger default_create_time_column before insert on app_token_global
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_global
    for each row execute procedure update_time_column();

  create trigger update_version_column before update on app_token_global
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token_global
    for each row execute procedure immutable_columns('public_id', 'created_time', 'scope_id');

  create trigger insert_app_token_subtype before insert on app_token_global
    for each row execute procedure insert_app_token_subtype();

  -- App token permissions global table
  create table app_token_permission_global (
    private_id wt_private_id primary key,
    app_token_id wt_public_id
      constraint app_token_global_fkey
        references app_token_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_global_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    label text,
    grant_this_scope boolean not null default false,
    grant_scope text not null
      constraint app_token_global_grant_scope_enm_fkey
        references app_token_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    created_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_private_id_uq
      unique(grant_scope, private_id)
  );
  comment on table app_token_permission_global is
    'app_token_permission_global contains global scope-specific permissions for app tokens.';

  -- Add triggers for app_token_permission_global
  create trigger default_create_time_column before insert on app_token_permission_global
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global
    for each row execute procedure immutable_columns('app_token_id', 'scope_id', 'label', 'grant_scope', 'grant_this_role_scope', 'created_time');

  create table app_token_permission_global_individual_org_grant_scope (
    permission_id wt_private_id
      constraint app_token_permission_global_fkey
      references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permission_global
    -- grant_scope, it ensures that app_token_permission_global is set to 'individual'
    -- if this table is populated for the corresponding permission.
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope = 'individual'
        ), 
    created_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_fkey
      foreign key (grant_scope, permission_id)
      references app_token_permission_global(grant_scope, private_id)
      on delete cascade
      on update cascade,
    primary key(grant_scope, permission_id)
  );
  comment on table app_token_permission_global_individual_org_grant_scope is
    'app_token_permission_global_individual_org_grant_scope is a list of individually granted org scope to global app token permissions with grant_scope of individual.';

  -- Add trigger for app_token_permission_global_individual_org_grant_scope
  create trigger default_create_time_column before insert on app_token_permission_global_individual_org_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global_individual_org_grant_scope
    for each row execute procedure immutable_columns('scope_id', 'grant_scope', 'created_time');

  create table app_token_permission_global_individual_project_grant_scope (
    permission_id wt_private_id
      constraint app_token_permission_global_fkey
      references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permission_global
    -- grant_scope, it ensures that app_token_permission_global is set to 'individual'
    -- if this table is populated for the corresponding permission.
    -- both children and individual are allowed for this global permission
    -- because projects can be individually in addition to children 
    -- which grants all orgs
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope in ('individual', 'children')
        ),
    created_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_fkey
      foreign key (grant_scope, permission_id)
      references app_token_permission_global(grant_scope, private_id)
      on delete cascade
      on update cascade,
    primary key(grant_scope, permission_id)
  );
  comment on table app_token_permission_global_individual_project_grant_scope is
    'app_token_permission_global_individual_project_grant_scope is a list of individually granted project scope table to global app token permissions with grant_scope of individual or children.';

  -- Add trigger for app_token_permission_global_individual_project_grant_scope
  create trigger default_create_time_column before insert on app_token_permission_global_individual_project_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global_individual_project_grant_scope
    for each row execute procedure immutable_columns('scope_id', 'grant_scope', 'created_time');

  create table app_token_permission_global_grant (
    permission_id wt_private_id
      constraint app_token_permission_global_fkey
      references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    canonical_grant wt_canonical_grant not null
      constraint app_token_permission_resource_grant_fkey
        references app_token_permission_resource_grant(canonical_grant)
        on delete cascade
        on update cascade,
    raw_grant text not null
      constraint raw_grant_must_not_be_empty
      check(
        length(trim(raw_grant)) > 0
      ),
    primary key(permission_id, canonical_grant)
  );
  comment on table app_token_permission_global_grant is
    'app_token_permission_global_grant contains grants assigned to app tokens in global scope.';

  create table app_token_permission_global_deleted_scope (
    permission_id wt_private_id primary key
      constraint app_token_permission_global_deleted_scope_fkey
        references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    scope_hst_id iam_scope_hst not null,
    delete_time wt_timestamp not null
  );
  comment on table app_token_permission_global_deleted_scope is
    'app_token_permission_global_deleted_scope holds the ID and delete_time of every deleted app token';

  -- Function to track deleted individual grant scopes
  create or replace function insert_deleted_app_token_permission_global_individual_grant_scope()
  returns trigger as $$
  begin
    insert into app_token_permission_global_deleted_scope (permission_id, scope_hst_id, delete_time)
    values (OLD.permission_id, OLD.scope_id, now())
    on conflict (permission_id) do update set
      scope_hst_id = EXCLUDED.scope_hst_id,
      delete_time = EXCLUDED.delete_time;
    return OLD;
  end;
  $$ language plpgsql;

  -- Trigger for org grant scope deletions
  create trigger insert_app_token_permissions_global_deleted_individual_org_grant_scope_trigger
    after delete on app_token_permission_global_individual_org_grant_scope
    for each row execute function insert_deleted_app_token_permission_global_individual_grant_scope();

  -- Trigger for project grant scope deletions
  create trigger insert_app_token_permissions_global_deleted_individual_project_grant_scope_trigger
    after delete on app_token_permission_global_individual_project_grant_scope
    for each row execute function insert_deleted_app_token_permission_global_individual_grant_scope();

commit;