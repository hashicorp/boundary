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
    revoked boolean not null default false,
    create_time wt_timestamp,
    update_time wt_timestamp,
    created_by_user_id wt_user_id not null,
    approximate_last_access_time wt_timestamp
      constraint last_access_time_must_not_be_after_expiration_time
      check(
        approximate_last_access_time <= expiration_time
      ),
    time_to_stale_seconds integer not null default 0
      constraint time_to_stale_seconds_must_be_non_negative
        check(time_to_stale_seconds >= 0),
    expiration_time wt_timestamp
      constraint create_time_must_not_be_after_expiration_time
      check(
        create_time <= expiration_time
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

  create trigger default_create_time_column before insert on app_token_global
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_global
    for each row execute procedure update_time_column();

  create trigger update_version_column before update on app_token_global
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token_global
    for each row execute procedure immutable_columns('public_id', 'create_time', 'scope_id');

  create trigger insert_app_token_subtype before insert on app_token_global
    for each row execute procedure insert_app_token_subtype();

  create trigger validate_app_token_global_created_by_user_trigger before insert on app_token_global
    for each row execute function validate_app_token_created_by_user();

  -- App token permissions global table
  create table app_token_permission_global (
    private_id wt_private_id primary key,
    app_token_id wt_public_id
      constraint app_token_global_fkey
        references app_token_global(public_id)
        on delete cascade
        on update cascade,
    description text,
    grant_this_scope boolean not null default false,
    grant_scope text not null
      constraint app_token_global_grant_scope_enm_fkey
        references app_token_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_private_id_uq
      unique(grant_scope, private_id)
  );
  comment on table app_token_permission_global is
    'app_token_permission_global contains global scope-specific permissions for app tokens.';

  -- Create index on app_token_id for better query performance
  create index app_token_permission_global_app_token_id_idx on app_token_permission_global (app_token_id);

  -- Add triggers for app_token_permission_global
  create trigger default_create_time_column before insert on app_token_permission_global
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global
    for each row execute procedure immutable_columns('app_token_id', 'scope_id', 'label', 'grant_scope', 'grant_this_scope', 'create_time');

  create trigger insert_app_token_permission_subtype before insert on app_token_permission_global
    for each row execute procedure insert_app_token_permission_subtype();

  create table app_token_permission_global_individual_org_grant_scope (
    permission_id wt_private_id
      constraint app_token_permission_global_fkey
      references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null,
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
    create_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_fkey
      foreign key (grant_scope, permission_id)
      references app_token_permission_global(grant_scope, private_id)
      on delete cascade
      on update cascade,
    primary key(permission_id, scope_id)
  );
  comment on table app_token_permission_global_individual_org_grant_scope is
    'app_token_permission_global_individual_org_grant_scope is a list of individually granted org scope to global app token permissions with grant_scope of individual.';

  create or replace function validate_global_permission_org_scope() returns trigger
  as $$
  begin
    perform
       from iam_scope_org
      where iam_scope_org.scope_id = new.scope_id;
    if not found then 
      raise exception 'org scope_id % not found', new.scope_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
    comment on function validate_global_permission_org_scope() is
      'validate_global_permission_org_scope is used to enforced that scope ID added to app_token_permission_global_individual_project_grant_scope'
      'exists and is an org scope';

  -- Add trigger for app_token_permission_global_individual_org_grant_scope
  create trigger default_create_time_column before insert on app_token_permission_global_individual_org_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global_individual_org_grant_scope
    for each row execute procedure immutable_columns('scope_id', 'grant_scope', 'create_time');

  -- Trigger to validate org scope exists
  create trigger validate_global_permission_org_scope_trigger before insert on app_token_permission_global_individual_org_grant_scope
    for each row execute function validate_global_permission_org_scope();

  create table app_token_permission_global_individual_project_grant_scope (
    permission_id wt_private_id
      constraint app_token_permission_global_fkey
      references app_token_permission_global(private_id)
        on delete cascade
        on update cascade,
    -- scope_id does not have a foreign key constraint to iam_scope_project
    -- because we do not want to enforce that the project must exist
    -- the project may be deleted but that should not affect the app token permission grant scopes
    -- the application layer will query the DB to check if the project exists and makes appropriate decisions
    scope_id wt_scope_id not null,
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
    create_time wt_timestamp,
    constraint app_token_permission_global_grant_scope_fkey
      foreign key (grant_scope, permission_id)
      references app_token_permission_global(grant_scope, private_id)
      on delete cascade
      on update cascade,
    primary key(permission_id, scope_id)
  );
  comment on table app_token_permission_global_individual_project_grant_scope is
    'app_token_permission_global_individual_project_grant_scope is a list of individually granted project scope table to global app token permissions with grant_scope of individual or children.';

  create or replace function validate_global_permission_project_scope() returns trigger
  as $$
  begin
    perform
       from iam_scope_project
      where iam_scope_project.scope_id = new.scope_id;
    if not found then 
      raise exception 'project scope_id % not found', new.scope_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
    comment on function validate_global_permission_project_scope() is
      'validate_global_permission_project_scope is used to enforced that scope ID added to app_token_permission_global_individual_project_grant_scope'
      'exists and is a project scope';

  -- Add trigger for app_token_permission_global_individual_project_grant_scope
  create trigger default_create_time_column before insert on app_token_permission_global_individual_project_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_global_individual_project_grant_scope
    for each row execute procedure immutable_columns('scope_id', 'grant_scope', 'create_time');

  -- Trigger to validate project scope exists
  create trigger validate_global_permission_project_scope_trigger before insert on app_token_permission_global_individual_project_grant_scope
    for each row execute function validate_global_permission_project_scope();

commit;