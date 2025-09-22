-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1
begin;

  -- Main app_token table similar to iam_role structure
  create table app_token_project (
    public_id wt_public_id primary key
      constraint app_token_fkey
        references app_token(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_scope_id_fkey
        references iam_scope_project(scope_id)
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
    constraint app_token_project_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table app_token_project is
    'app_token_project is the table for application tokens in project scope';

  -- Add index for querying app_token by created_by (user)
  create index app_token_project_created_by_idx on app_token_project (created_by_user_hst_id);

  -- Add triggers for app_token
  create trigger default_create_time_column before insert on app_token_project
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_project
    for each row execute procedure update_time_column();

  create trigger update_version_column before update on app_token_project
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token_project
    for each row execute procedure immutable_columns('public_id', 'created_time', 'scope_id');

  create trigger insert_app_token_subtype before insert on app_token_project
    for each row execute procedure insert_app_token_subtype();

  -- App token permissions project table
  create table app_token_permission_project (
    private_id wt_private_id primary key,
    app_token_id wt_public_id
      constraint app_token_permission_fkey
        references app_token_project(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    label text,
    grant_this_role_scope boolean not null default false,
    version wt_version,
    created_time wt_timestamp
  );
  comment on table app_token_permission_project is
    'app_token_permission_project is a subtype table of the app_token_permission table. It is used to store permissions that are scoped to a project.';

  -- Add triggers for app_token_permission_project
  create trigger default_create_time_column before insert on app_token_permission_project
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_permission_project
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on app_token_permission_project
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token_permission_project
    for each row execute procedure immutable_columns('app_token_id', 'scope_id', 'label', 'grant_this_role_scope', 'grant_scope', 'version', 'created_time');

  create table app_token_permission_project_grant (
    permission_id wt_private_id
      constraint app_token_permission_project_grant_fkey
      references app_token_permission_project(private_id)
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
  comment on table app_token_permission_project_grant is
    'app_token_permission_project_grant contains grants assigned to app tokens in project scope.';

commit;
