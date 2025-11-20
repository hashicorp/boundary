-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1
begin;

  -- Main app_token table similar to iam_role structure
  create table app_token_org (
    public_id wt_public_id primary key
      constraint app_token_fkey
        references app_token(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_scope_id_fkey
        references iam_scope_org(scope_id)
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
    constraint app_token_org_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table app_token_org is
    'app_token_org is the table for application tokens in org scope';

  -- Add triggers for app_token
  create trigger default_create_time_column before insert on app_token_org
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_org
    for each row execute procedure update_time_column();

  create trigger revocation_check before update on app_token_org
    for each row execute procedure validate_app_token_revocation();

  create trigger approximate_last_access_time_column before update on app_token_org
    for each row execute procedure update_app_token_table_approximate_last_access_time();

  create trigger immutable_columns before update on app_token_org
    for each row execute procedure immutable_columns('public_id', 'create_time', 'scope_id', 'created_by_user_id', 'expiration_time', 'time_to_stale_seconds');

  create trigger insert_app_token_subtype before insert on app_token_org
    for each row execute procedure insert_app_token_subtype();

  create trigger validate_app_token_global_created_by_user_trigger before insert on app_token_org
    for each row execute function validate_app_token_created_by_user();

  -- App token permissions org table
  create table app_token_permission_org (
    private_id wt_private_id
      constraint app_token_permission_org_fkey
        references app_token_permission(private_id)
        on delete cascade
        on update cascade
        primary key,
    app_token_id wt_public_id
      constraint app_token_permission_fkey
        references app_token_org(public_id)
        on delete cascade
        on update cascade,
    description text,
    grant_this_scope boolean not null default false,
    grant_scope text not null
      constraint app_token_org_grant_scope_enm_fkey
        references app_token_org_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    -- Ensure this org permission belongs to the same app token as the base permission
    constraint app_token_permission_org_grant_scope_public_id_uq
      unique(grant_scope, private_id)
  );
  comment on table app_token_permission_org is
    'app_token_permission_org is a subtype table of the app_token_permission table. It is used to store permissions that are scoped to an org.';

  -- Create index on app_token_id for better query performance
  create index app_token_permission_org_app_token_id_idx on app_token_permission_org (app_token_id);

  -- Add triggers for app_token_permission_org
  create trigger default_create_time_column before insert on app_token_permission_org
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_permission_org
    for each row execute procedure update_time_column();

  create trigger immutable_columns before update on app_token_permission_org
    for each row execute procedure immutable_columns('app_token_id', 'scope_id', 'label', 'grant_this_scope', 'grant_scope', 'create_time');

  create trigger insert_app_token_permission_subtype before insert on app_token_permission_org
    for each row execute procedure insert_app_token_permission_subtype();


  create table app_token_permission_org_individual_grant_scope (
    permission_id wt_private_id
      constraint app_token_permission_org_fkey
        references app_token_permission_org(private_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permission_org
    -- grant_scope, it ensures that app_token_permission_org is set to 'individual'
    -- if this table is populated for the corresponding permission.
    grant_scope text not null
      constraint only_individual_grant_scope_allowed
        check(
            grant_scope = 'individual'
        ),
    constraint app_token_permission_org_grant_scope_fkey
      foreign key (grant_scope, permission_id)
      references app_token_permission_org(grant_scope, private_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    primary key(permission_id, scope_id)
  );
  comment on table app_token_permission_org_individual_grant_scope is
    'app_token_permission_org_individual_grant_scope is a list of individually granted project scope to org app token permissions with grant_scope of individual';

  create function validate_org_permission_project_scope_and_parent() returns trigger
  as $$
  declare
    org_scope_id wt_scope_id;
  begin
    -- First get the org scope_id for this permission
    select app_token_org.scope_id
      into org_scope_id
      from app_token_permission_org
      join app_token_org
        on app_token_org.public_id = app_token_permission_org.app_token_id
     where app_token_permission_org.private_id = new.permission_id;

    if not found then
      raise exception 'permission_id % not found or has no associated app token', new.permission_id;
    end if;

    -- Then validate that the project exists and belongs to this org
    perform
      from iam_scope_project
     where iam_scope_project.scope_id = new.scope_id
       and iam_scope_project.parent_id = org_scope_id;

    if not found then
      raise exception 'project scope_id % not found or is not a child of org %', new.scope_id, org_scope_id;
    end if;

    return new;
  end;
  $$ language plpgsql;  comment on function validate_org_permission_project_scope_and_parent() is
    'validate_org_permission_project_scope_and_parent ensures the project exists and belongs to the org of the token scope.';

  -- Add trigger for app_token_permission_org_individual_grant_scope
  create trigger default_create_time_column before insert on app_token_permission_org_individual_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission_org_individual_grant_scope
    for each row execute procedure immutable_columns('app_token_id', 'scope_id', 'grant_scope', 'create_time');

  -- Trigger to validate project scope relationship
  create trigger validate_org_permission_project_scope_and_parent_trigger before insert on app_token_permission_org_individual_grant_scope
    for each row execute function validate_org_permission_project_scope_and_parent();

commit;