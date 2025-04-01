-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Create the enumeration table for the grant scope types for the global iam_role
  create table iam_role_global_grant_scope_enm (
    name text primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'descendants',
            'children',
            'individual'
          )
        )
  );
  comment on table iam_role_global_grant_scope_enm is
    'iam_role_global_grant_scope_enm is an enumeration table for role grant scope types for the iam_role_global table.';

  -- Insert the predefined grant scope types for iam_role_global
  insert into iam_role_global_grant_scope_enm (name)
  values
    ('descendants'),
    ('children'),
    ('individual');

  create function insert_role_subtype() returns trigger
  as $$
  begin
    insert into iam_role
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_role_subtype() is
    'insert_role_subtype is used to automatically insert a row into the iam_role table '
    'whenever a row is inserted into the subtype table';

  create function insert_grant_scope_update_time() returns trigger
  as $$
  begin
    if new.grant_scope is distinct from old.grant_scope then
      new.grant_scope_update_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_grant_scope_update_time() is
    'insert_grant_scope_update_time is used to automatically update the grant_scope_update_time '
    'of the subtype table whenever the grant_scope column is updated';

  create function insert_grant_this_role_scope_update_time() returns trigger
  as $$
  begin
    if new.grant_this_role_scope is distinct from old.grant_this_role_scope then
      new.grant_this_role_scope_update_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_grant_this_role_scope_update_time() is
    'insert_grant_this_role_scope_update_time is used to automatically update the grant_scope_update_time '
    'of the subtype table whenever the grant_this_role_scope column is updated';

  create function delete_iam_role_subtype() returns trigger
  as $$
  begin
    delete from iam_role
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
    $$ language plpgsql;
    comment on function delete_iam_role_subtype() is
      'delete_iam_role_subtype is used to automatically delete associated iam_role entry'
      'since domain implementation performs deletion on the child table which does not cleanup the base iam_role table ';

-- Add trigger to update the new update_time column on every iam_role subtype update.
  create function update_iam_role_table_update_time() returns trigger
  as $$
  begin
    update iam_role set update_time = new.update_time where public_id = new.public_id;
    return new;
  end;
    $$ language plpgsql;
    comment on function update_iam_role_table_update_time() is
      'update_iam_role_table_update_time is used to automatically update the update_time '
      'of the base table whenever one of the subtype iam_role tables are updated';


  -- global iam_role must have a scope_id of global.
  --
  -- grant_this_role_scope indicates if the role can apply its grants to the scope.
  -- grant_scope indicates the scope of the grants. 
  -- grant_scope can be 'descendants', 'children', or 'individual'.
  --
  -- grant_this_role_scope_update_time and grant_scope_update_time are used to track 
  -- the last time the grant_this_role_scope and grant_scope columns were updated.
  -- This is used to represent the grant scope create_time column from the 
  -- iam_role_grant_scope table in 83/01_iam_role_grant_scope.up.sql.
  -- This matches the representation of the existing create_time field at the 
  -- role domain layer that indicates when the grant scope was created.
  create table iam_role_global (
    public_id wt_role_id primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_global_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint iam_role_global_grant_scope_enm_fkey
        references iam_role_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    constraint iam_role_global_grant_scope_public_id_uq
      unique(grant_scope, public_id),
    constraint iam_role_global_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table iam_role_global is
    'iam_role_global is the subtype table for the global role. grant_this_role_scope_update_time and grant_scope_update_time are used to track the last time the grant_this_role_scope and grant_scope columns were updated.';

  create trigger insert_role_subtype before insert on iam_role_global
    for each row execute procedure insert_role_subtype();

  create trigger insert_grant_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();

  create trigger insert_grant_this_role_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_global_grant_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();

  create trigger update_iam_role_global_grant_this_role_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_table_update_time after update on iam_role_global
    for each row execute procedure update_iam_role_table_update_time();

  create trigger delete_iam_role_subtype after delete on iam_role_global
    for each row execute procedure delete_iam_role_subtype();

  create trigger default_create_time_column before insert on iam_role_global
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on iam_role_global
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_global
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on iam_role_global
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create table iam_role_global_individual_org_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_global
    -- grant_scope, it ensures that iam_role_global is set to 'individual'
    -- if this table is populated for the corresponding role.
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope = 'individual'
        ), 
    constraint iam_role_global_grant_scope_fkey
      foreign key (role_id, grant_scope)
      references iam_role_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    primary key(role_id, scope_id)
  );
  comment on table iam_role_global_individual_org_grant_scope is
    'iam_role_global_individual_org_grant_scope is a list of individually granted org scope to global roles with grant_scope of individual.';

  create trigger default_create_time_column before insert on iam_role_global_individual_org_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_global_individual_org_grant_scope
    for each row execute procedure immutable_columns('role_id', 'grant_scope', 'scope_id', 'create_time');

  create table iam_role_global_individual_project_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_global
    -- grant_scope, it ensures that iam_role_global is set to 'individual'
    -- if this table is populated for the corresponding role.
    -- both children and individual are allowed for this global role
    -- because projects can be individually in addition to children 
    -- which grants all orgs
    grant_scope text not null
       constraint only_individual_or_children_grant_scope_allowed
         check(
          grant_scope in ('individual', 'children')
        ),
    constraint iam_role_global_grant_scope_fkey
      foreign key (role_id, grant_scope)
      references iam_role_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    primary key(role_id, scope_id)
  );
  comment on table iam_role_global_individual_project_grant_scope is
    'iam_role_global_individual_project_grant_scope is a list of individually granted project scope table to global role with grant_scope of individual or children.';

  create trigger default_create_time_column before insert on iam_role_global_individual_project_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_global_individual_project_grant_scope
    for each row execute procedure immutable_columns('role_id', 'grant_scope', 'scope_id', 'create_time');


commit;