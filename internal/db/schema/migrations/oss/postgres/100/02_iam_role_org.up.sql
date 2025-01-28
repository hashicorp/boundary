-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table iam_role_org_grant_scope_enm (
    name text not null primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'children',
            'individual'
          )
        )
  );

  insert into iam_role_org_grant_scope_enm (name)
  values
    ('children'),
    ('individual');       

  create table iam_role_org (
    public_id wt_role_id not null primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null,
    grant_scope text
      constraint iam_role_org_grant_scope_enm_fkey
        references iam_role_org_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    updated_at wt_timestamp,
    unique(public_id, grant_scope)
  );

  create trigger insert_role_subtype before insert on iam_role_org
    for each row execute procedure insert_role_subtype();

  create trigger insert_iam_role_org_grant_scope_update_time before insert on iam_role_org
    for each row execute procedure insert_grant_scope_update_time();

  create trigger insert_iam_role_org_grant_this_role_scope_update_time before insert on iam_role_org
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_org_grant_scope_update_time before update on iam_role_org
    for each row execute procedure insert_grant_scope_update_time();

  create trigger update_iam_role_org_grant_this_role_scope_update_time before update on iam_role_org
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger default_create_time_column before insert on iam_role_org
    for each row execute procedure default_create_time();

  create trigger update_iam_role_table_update_time before update on iam_role_org
    for each row execute procedure update_iam_role_table_update_time();

  create trigger immutable_columns before update on iam_role_org
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create table iam_role_org_individual_grant_scope (
    role_id wt_role_id
      constraint iam_role_org_fkey
        references iam_role_org(public_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_org
    -- grant_scope, it ensures that iam_role_org is set to 'individual'
    -- if this table is populated for the corresponding role.
    grant_scope text
      constraint only_individual_grant_scope_allowed
        check(
            grant_scope = 'individual'
        ),
    scope_id wt_scope_id
      constraint iam_scope_org_scope_id_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    constraint iam_role_org_grant_scope_fkey 
      foreign key (role_id, grant_scope)
      references iam_role_org(public_id, grant_scope),
    create_time wt_timestamp
  );

  create trigger default_create_time_column before insert on iam_role_org_individual_grant_scope
  for each row execute procedure default_create_time();

  -- ensure the project's parent is the role's scope
  create or replace function ensure_project_belongs_to_role_org() returns trigger
  as $$
  declare
    org_scope_id text;
    project_parent_id text;
  begin
  -- Find the org scope for this role
  select scope_id
    into org_scope_id
    from iam_role_org
   where public_id = new.role_id;

  if org_scope_id is null then
    raise exception 'role % not found in iam_role_org', new.role_id;
  end if;

  -- Find the project parent for the inserted scope_id
  select parent_id
    into project_parent_id
    from iam_scope_project
   where scope_id = new.scope_id;

  if project_parent_id is null then
    raise exception 'project scope_id % not found in iam_scope_project', new.scope_id;
  end if;

  -- Compare parent_id with the org scope
  if project_parent_id != org_scope_id then
    raise exception 'project % belongs to a different org',
      new.scope_id;
  end if;

  return new;
  end;
  $$ language plpgsql;

  create trigger ensure_project_belongs_to_role_org before insert or update on iam_role_org_individual_grant_scope
    for each row execute procedure ensure_project_belongs_to_role_org();

commit;