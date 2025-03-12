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
      unique(grant_scope, public_id)
  );
  comment on table iam_role_global is
    'iam_role_global is the subtype table for the global role. grant_this_role_scope_update_time and grant_scope_update_time are used to track the last time the grant_this_role_scope and grant_scope columns were updated.';  

  create trigger update_iam_role_global_grant_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();

  create trigger update_iam_role_global_grant_this_role_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_time_column before update on iam_role_global
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_global 
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on iam_role_global
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create table iam_role_global_individual_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade
      constraint scope_id_is_not_global
        check(
          scope_id != 'global'
        ),
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
  comment on table iam_role_global_individual_grant_scope is
    'iam_role_global_individual_grant_scope is the subtype table for the global role with grant_scope as individual.';

  create trigger immutable_columns before update on iam_role_global_individual_grant_scope
    for each row execute procedure immutable_columns('role_id', 'grant_scope', 'scope_id', 'create_time');

  with aggregated_iam_role_grant_scope as (
    select
      r.role_id,
      json_agg(
        json_build_object(
          'create_time', r.create_time,
          'scope_id_or_special', r.scope_id_or_special
        )
        order by r.create_time
      ) as grant_scope
    from iam_role_grant_scope r
    group by r.role_id
  ),
  grant_scope_values as (
  select
    a.role_id,
    -- if scope_id_or_special is 'this' set grant_this_role_scope to true
    -- if scope_id_or_special is 'global' set grant_this_role_scope to true
    -- if neither are present set grant_this_role_scope to false
    exists (
      select 1
        from jsonb_array_elements(a.grant_scope::jsonb) arr
       where arr->>'scope_id_or_special' = 'this' or arr->>'scope_id_or_special' = 'global'
    ) as grant_this_role_scope,
    -- if scope_id_or_special is 'descendants' set grant_scope to 'descendants'.
    -- if scope_id_or_special is 'children' set grant_scope to 'children'.
    -- if neither are present set grant_scope to 'individual' because
    -- the value could be a scope_id in which case the grant_scope should be 'individual'.
    -- if the value is 'this' then the grant_scope should be 'individual' as well
    -- because the grant_scope column cannot be null.
    case
      when exists (
        select 1
          from jsonb_array_elements(a.grant_scope::jsonb) arr
         where arr->>'scope_id_or_special' = 'descendants'
      ) then 'descendants'
      when exists (
        select 1
          from jsonb_array_elements(a.grant_scope::jsonb) arr
         where arr->>'scope_id_or_special' = 'children'
      ) then 'children'
      else 'individual'
    end as grant_scope,
    -- there should only be one create_time for when scope_id_or_special is 'this'
    -- so we can just pick the first create_time for this value
    (select (x->>'create_time')::wt_timestamp
     from jsonb_array_elements(a.grant_scope::jsonb) x
     where x->>'scope_id_or_special' = 'this'
     order by (x->>'create_time')::wt_timestamp
     limit 1
    ) as grant_this_role_scope_update_time,
    -- if scope_id_or_special is not 'this' then we can just pick the first create_time.
    (select (x->>'create_time')::wt_timestamp
     from jsonb_array_elements(a.grant_scope::jsonb) x
     where x->>'scope_id_or_special' != 'this'
     order by (x->>'create_time')::wt_timestamp
     limit 1
    ) as grant_scope_update_time
  from aggregated_iam_role_grant_scope a
  )
  insert into iam_role_global (
    public_id,
    scope_id,
    name,
    description,
    version,
    grant_this_role_scope,
    grant_scope,
    grant_this_role_scope_update_time,
    grant_scope_update_time,
    create_time,
    update_time
  )
  select
    r.public_id,
    r.scope_id,
    r.name,
    r.description,
    r.version,
    rs.grant_this_role_scope,
    rs.grant_scope,
    rs.grant_this_role_scope_update_time,
    rs.grant_scope_update_time,
    r.create_time,
    r.update_time
  from grant_scope_values rs
  join iam_role r on rs.role_id = r.public_id
  join iam_scope s on s.public_id = r.scope_id
  where s.type = 'global';

  -- migrate data from iam_role_grant_scope to iam_role_global_individual_grant_scope
  insert into iam_role_global_individual_grant_scope (
    role_id,
    grant_scope,
    scope_id,
    create_time
  )
  select
    rs.role_id,
    'individual',
    rs.scope_id_or_special,
    rs.create_time
  from iam_role_grant_scope rs
  join iam_role r         on r.public_id = rs.role_id
  join iam_scope s        on s.public_id = r.scope_id
  where
    s.type = 'global' and
    rs.scope_id_or_special not in ('this','children','descendants') and
    rs.scope_id_or_special != 'global';

  create trigger insert_role_subtype before insert on iam_role_global
    for each row execute procedure insert_role_subtype();

  create trigger insert_grant_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();  

  create trigger insert_grant_this_role_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger default_create_time_column before insert on iam_role_global
    for each row execute procedure default_create_time();

  create trigger default_create_time_column before insert on iam_role_global_individual_grant_scope
    for each row execute procedure default_create_time();

commit;