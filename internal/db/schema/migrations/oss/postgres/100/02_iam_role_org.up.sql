-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
 
  -- Create the enumeration table for the grant scope types for the org iam_role
  create table iam_role_org_grant_scope_enm (
    name text primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'children',
            'individual'
          )
        )
  );
  comment on table iam_role_org_grant_scope_enm is
  'iam_role_org_grant_scope_enm is an enumeration table for role grant scope types for the iam_role_org table.';

  -- Insert the predefined grant scope types for iam_role_org
  insert into iam_role_org_grant_scope_enm (name)
  values
    ('children'),
    ('individual');       

  create table iam_role_org (
    public_id wt_role_id primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint iam_role_org_grant_scope_enm_fkey
        references iam_role_org_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(public_id, grant_scope)
  );
  comment on table iam_role_org is
    'iam_role_org is a subtype table of the iam_role table. It is used to store roles that are scoped to an org.';

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

  create trigger update_time_column before update on iam_role_org
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_org
    for each row execute procedure update_version_column();

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
    scope_id wt_scope_id not null
      constraint iam_scope_org_scope_id_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    constraint iam_role_org_grant_scope_fkey 
      foreign key (role_id, grant_scope)
      references iam_role_org(public_id, grant_scope),
    create_time wt_timestamp
  );
  comment on table iam_role_org_individual_grant_scope is
    'iam_role_global_individual_grant_scope is the subtype table for the org role with grant_scope as individual.';

  create trigger default_create_time_column before insert on iam_role_org_individual_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_org_individual_grant_scope
    for each row execute procedure immutable_columns('role_id', 'grant_scope', 'scope_id', 'create_time');

  -- ensure the project's parent is the role's scope
  create function ensure_project_belongs_to_role_org() returns trigger
  as $$
  begin
    perform
       from iam_scope_project
       join iam_role_org 
         on iam_role_org.scope_id      = iam_scope_project.parent_id 
      where iam_scope_project.scope_id = new.scope_id
        and iam_role_org.public_id     = new.role_id; 
    if not found then 
      raise exception 'project scope_id % not found in org', new.scope_id;
    end if;
  return new;
  end;
  $$ language plpgsql;
  comment on function ensure_project_belongs_to_role_org() is
    'ensure_project_belongs_to_role_org ensures the project belongs to the org of the role.';

  create trigger ensure_project_belongs_to_role_org before insert or update on iam_role_org_individual_grant_scope
    for each row execute procedure ensure_project_belongs_to_role_org();

commit;