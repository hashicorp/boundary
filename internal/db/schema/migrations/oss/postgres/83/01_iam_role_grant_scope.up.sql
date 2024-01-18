-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  -- Create the new join table
  create table iam_role_grant_scope (
    create_time wt_timestamp,
    role_id wt_role_id -- pk
      references iam_role(public_id)
      on delete cascade
      on update cascade,
    scope_id text -- pk
      constraint scope_id_must_not_be_empty
      check(
        length(trim(scope_id)) > 0
      ),
    primary key(role_id, scope_id)
  );

  insert into oplog_ticket (name, version)
    values
    ('iam_role_grant_scope', 1);
  
  create trigger default_create_time_column before insert on iam_role_grant_scope
    for each row execute procedure default_create_time();

  -- iam_immutable_role_grant_scope() ensures that grant scopes assigned to
  -- roles are immutable. 
  create or replace function iam_immutable_role_grant_scope() returns trigger
  as $$
  begin
    raise exception 'role grant scopes are immutable';
  end;
  $$ language plpgsql;

  create trigger immutable_role_grant_scope before update on iam_role_grant_scope
    for each row execute procedure iam_immutable_role_grant_scope();
  
  -- cascade_role_grant_scope_deletion() ensures that grant scopes entries are
  -- deleted when scopes are deleted
  create or replace function cascade_role_grant_scope_deletion() returns trigger
  as $$
  begin
    delete from iam_role_grant_scope where scope_id = old.public_id;
    return old;
  end;
  $$ language plpgsql;

  -- Create a trigger to ensure scope deletion cascades, since we're not using wt_scope_id
  create trigger cascade_deletion_iam_scope_to_iam_role_grant_scope after delete on iam_scope
    for each row execute procedure cascade_role_grant_scope_deletion();

  -- role_grant_scope_id_valid ensures that a given grant scope ID is for a
  -- scope that exists or one of our known values
  create or replace function role_grant_scope_id_valid() returns trigger
  as $$
  declare new_scope_type text;
  declare role_scope_id text;
  declare parent_scope_id text;
  declare role_scope_type text;
  begin
    -- It's always allowed to have a scope_id of "this"
    if new.scope_id = 'this' then
      return new;
    end if;
    -- Fetch the scope id for the role
    select ir.scope_id from iam_role ir where ir.public_id = new.role_id into role_scope_id;
    -- It's always allowed to have the scope_id be the same as the role's
    if new.scope_id = role_scope_id then
      return new;
    end if;

    -- A note about the above: this technically allows us to have grant scope
    -- IDs defined on projects. The original grant_scope_id logic allowed this
    -- in the domain layer so long as it referred only to its own scope.
    -- Accordingly we keep this behavior, even though we could choose to
    -- disallow this at the API layer.

    -- At this point we've covered the same-as-role-scope and "this" cases
    -- above. Now, fetch the type of the role's scope, then check two situations
    -- that are either always or never allowed.
    select isc.type from iam_scope isc where isc.public_id = role_scope_id into role_scope_type;

    -- Always allowed, because any scope is a child of global, and we've handled
    -- same-scope-id case above; however we have to check the scope is actually
    -- valid/known. Distinction check is used because if it's not known it's
    -- null.
    if role_scope_type = 'global' then
      if new.scope_id != 'children' and new.scope_id != 'descendants' then
        select isc.public_id from iam_scope isc where isc.public_id = new.scope_id into role_scope_id;
        if role_scope_id is distinct from new.scope_id then
          raise exception 'invalid grant scope id';
        end if;
      end if;
      return new;
    end if;

    -- Never allowed, because projects don't have child scopes (and we've
    -- already allowed same-scope-id above)
    if role_scope_type = 'project' then
      raise exception 'invalid to set a grant scope ID to non-same scope_id when role scope type is project';
    end if;

    -- Ensure that what remains really is org
    if role_scope_type != 'org' then
      raise exception 'unknown scope type';
    end if;
    -- If it's "children" then allow it
    if new.scope_id = 'children' then
      return new;
    end if;
    -- Make "descendants" an error for orgs
    if new.scope_id = 'descendants' then
      raise exception 'invalid to specify "descendants" as a grant scope when the role''s scope ID is not "global"';
    end if;

    -- We are now dealing with a bare scope ID and need to ensure that it's a
    -- child project of the role's org scope. Look up the parent scope ID for
    -- the grant scope ID given in the row. Allow iff the grant scope ID's
    -- parent matches the role's scope ID. We know that the role is in an org
    -- scope, so the only acceptable possibility here is that the new scope ID
    -- is a project and its parent scope is this org's.

    -- Ensure it exists
    select isc.public_id from iam_scope isc where isc.public_id = new.scope_id into role_scope_id;
    if role_scope_id is distinct from new.scope_id then
      raise exception 'invalid grant scope id';
    end if;

    -- Ensure it's a project
    select isc.type from iam_scope isc where isc.public_id = new.scope_id into new_scope_type;
    if new_scope_type != 'project' then
      raise exception 'expected grant scope id scope type to be project';
    end if;

    -- Ensure that the parent of the project is the role's org scope
    select isc.parent_id from iam_scope isc where isc.public_id = new.scope_id into parent_scope_id;
    if parent_scope_id != role_scope_id then
      raise exception 'grant scope id is not a child project of the role org scope';
    end if;
    
    return new;
  end;
  $$ language plpgsql;
  comment on function role_grant_scope_id_valid() is
    'function used to ensure grant scope ids are valid';

  create trigger ensure_role_grant_scope_id_valid before insert or update on iam_role_grant_scope
    for each row execute procedure role_grant_scope_id_valid();
  
  -- Add a function that is used in our GrantsForUser CTE to turn grants
  -- containing "this", "children", or "descendants" into the actual scope IDs
  -- that can be used to build the grants for the request.
  create or replace function
    explodeRoleGrantScopes(roleIds text[], roleScopeIds text[], grantScopeIds text[])
  returns
    table(role_id text, grant_scope_id text)
  as $$
    declare
      idx int := 1;
      roleId text;
    begin
      foreach roleId in array roleIds
      loop
        case
          when grantScopeIds[idx] = 'descendants' then
            return query
              select
                roleIds[idx]::text as role_id, public_id::text as grant_scope_id from iam_scope
              where
                iam_scope.public_id != 'global';
          when grantScopeIds[idx] = 'children' then
            return query
              select
                roleIds[idx]::text as role_id, public_id::text as grant_scope_id from iam_scope
              where
                iam_scope.parent_id = roleScopeIds[idx];
          when grantScopeIds[idx] = 'this' then
            return query
              select
                roleIds[idx]::text as role_id, roleScopeIds[idx]::text as grant_scope_id;
          else
            return query
              select
                roleIds[idx]::text as role_id, grantScopeIds[idx]::text as grant_scope_id;
          end case;
      idx := idx + 1;
      end loop;
      return;
    end;
  $$ language plpgsql;

  -- Now perform migrations:

  -- First, copy current grant scope ID values from existing roles to the new
  -- table and set the grant scope ID value on each role to the scope ID
  insert into iam_role_grant_scope(role_id, scope_id)
    select public_id as role_id, grant_scope_id as scope_id from iam_role;

  -- Drop the now-unnecessary trigger and function from 0/06_iam
  drop trigger ensure_grant_scope_id_valid on iam_role;
  drop function grant_scope_id_valid;

  -- Remove the column from iam_role
  alter table iam_role drop column grant_scope_id;

commit;
