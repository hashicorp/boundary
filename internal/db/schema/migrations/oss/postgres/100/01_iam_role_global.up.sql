-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table iam_role_global_grant_scope_enm (
    name text not null primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'descendants',
            'children',
            'individual'
          )
        )
  );

  insert into iam_role_global_grant_scope_enm (name)
  values
    ('descendants'),
    ('children'),
    ('individual');

  create or replace function insert_role_subtype() returns trigger
  as $$
  begin
    insert into iam_role
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function insert_grant_scope_update_time() returns trigger
  as $$
  begin
    if new.grant_scope is distinct from old.grant_scope then
      new.grant_scope_update_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;

  create or replace function insert_grant_this_role_scope_update_time() returns trigger
  as $$
  begin
    if new.grant_this_role_scope is distinct from old.grant_this_role_scope then
      new.grant_scope_update_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;

  -- Add trigger to update the new column on every iam_role subtype update.
  -- This is used to update the update_time of the iam_role table
  -- when either the name or the description of the subtype tables are updated.
  -- This is only applicable to the name and description columns because we
  -- do not want the update_time to be updated when the grant_scope or grant_this_role_scope
  -- columns are updated.
  create function update_iam_role_table_update_time() returns trigger
  as $$
  begin
    if (new.name is distinct from old.name) or (new.description is distinct from old.description) then
      update iam_role set update_time = now() where public_id = new.public_id;
      return new;
    end if;  
  end;
  $$ language plpgsql;
  comment on function update_iam_role_table_update_time() is
    'update_iam_role_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- global iam_role must have a scope_id of global
  create table iam_role_global (
    public_id wt_role_id not null primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id
      constraint iam_scope_global_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    grant_scope text
      constraint iam_role_global_grant_scope_enm_fkey
        references iam_role_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(public_id, grant_scope)
  );

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

  create trigger default_create_time_column before insert on iam_role_global
    for each row execute procedure default_create_time();

  create trigger update_iam_role_table_update_time before update on iam_role_global
    for each row execute procedure update_iam_role_table_update_time();

  create trigger immutable_columns before update on iam_role_global
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create table iam_role_global_individual_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_global
    -- grant_scope, it ensures that iam_role_global is set to 'individual'
    -- if this table is populated for the corresponding role.
    grant_scope text
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope = 'individual'
        ),
    scope_id wt_scope_id
      constraint iam_scope_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade
      constraint scope_id_is_not_global
        check(
          scope_id != 'global'
        ),
    constraint iam_role_global_grant_scope_fkey
      foreign key (role_id, grant_scope)
      references iam_role_global(public_id, grant_scope),
    create_time wt_timestamp
  );

  create trigger default_create_time_column before insert on iam_role_global_individual_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_global_individual_grant_scope
    for each row execute procedure immutable_columns('scope_id', 'create_time');

commit;