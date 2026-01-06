-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: MPL-2.0

begin;

  -- This table is a join table to map roles to the various scopes the role
  -- grants apply to. role_id is a foreign key, but scope_id_or_special is not a
  -- foreign key to scopes because we support specific special values which are
  -- checked for in the constraint. We never query by scope_id_or_special so the
  -- ordering of the primary key should be correct.
  create table iam_role_grant_scope (
    create_time wt_timestamp,
    role_id wt_role_id not null -- pk
      references iam_role(public_id)
      on delete cascade
      on update cascade,
    scope_id_or_special text not null -- pk
      constraint scope_id_or_special_is_valid
      check (
        length(trim(scope_id_or_special)) = 12
          or
        scope_id_or_special in ('global', 'this', 'children', 'descendants')
      ),
    primary key(role_id, scope_id_or_special)
  );
  comment on table iam_role_grant_scope is
    'table to map roles to the scopes they grant access to';

  insert into oplog_ticket (name, version)
    values
    ('iam_role_grant_scope', 1);

  create trigger default_create_time_column before insert on iam_role_grant_scope
    for each row execute procedure default_create_time();

  -- iam_immutable_role_grant_scope() ensures that grant scopes assigned to
  -- roles are immutable. 
  create function iam_immutable_role_grant_scope() returns trigger
  as $$
  begin
    raise exception 'role grant scopes are immutable';
  end;
  $$ language plpgsql;

  create trigger immutable_role_grant_scope before update on iam_role_grant_scope
    for each row execute procedure iam_immutable_role_grant_scope();
  
  -- cascade_role_grant_scope_deletion() ensures that grant scopes entries are
  -- deleted when scopes are deleted
  create function cascade_role_grant_scope_deletion() returns trigger
  as $$
  begin
    delete from iam_role_grant_scope where scope_id_or_special = old.public_id;
    return old;
  end;
  $$ language plpgsql;

  -- Create a trigger to ensure scope deletion cascades, since we're not using wt_scope_id
  create trigger cascade_deletion_iam_scope_to_iam_role_grant_scope after delete on iam_scope
    for each row execute procedure cascade_role_grant_scope_deletion();

  -- role_grant_scope_id_or_special_valid ensures that a given grant scope ID is for a
  -- scope that exists or one of our known values
  create function role_grant_scope_id_or_special_valid() returns trigger
  as $$
  declare new_scope_type text;
  declare role_scope_id text;
  declare parent_scope_id text;
  declare role_scope_type text;
  declare validated_scope_id text;
  declare existing_scope_id_or_special text;
  begin
    -- We want to make a few checks based on the role's actual scope so select it
    select ir.scope_id from iam_role ir where ir.public_id = new.role_id into role_scope_id;
    -- It's always allowed to have a scope_id_or_special of "this" but don't
    -- allow it as well as the role's explicit scope ID
    if new.scope_id_or_special = 'this' then
      select rgs.scope_id_or_special
        from iam_role_grant_scope rgs
        where rgs.role_id = new.role_id and rgs.scope_id_or_special = role_scope_id
        into existing_scope_id_or_special;
      if existing_scope_id_or_special is not null then
        raise exception 'invalid to specify both a role''s actual scope id and "this" as a grant scope';
      end if;
      return new;
    end if;
    -- Fetch the scope id for the role
    select ir.scope_id from iam_role ir where ir.public_id = new.role_id into role_scope_id;
    -- It's always allowed to have the scope_id_or_special be the same as the role's
    if new.scope_id_or_special = role_scope_id then
      select rgs.scope_id_or_special
        from iam_role_grant_scope rgs
        where rgs.role_id = new.role_id and rgs.scope_id_or_special = 'this'
        into existing_scope_id_or_special;
      if existing_scope_id_or_special is not null then
        raise exception 'invalid to specify both "this" and a role''s actual scope id as a grant scope';
      end if;
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
    -- valid/known. Distinction check is used in the final case because if it's
    -- not known it's null.
    if role_scope_type = 'global' then
      case
        when new.scope_id_or_special = 'children' then
          select rgs.scope_id_or_special
            from iam_role_grant_scope rgs
            where rgs.role_id = new.role_id and rgs.scope_id_or_special = 'descendants'
            into existing_scope_id_or_special;
          if existing_scope_id_or_special is not null then
            raise exception 'invalid to specify both "descendants" and "children" as a grant scope';
          end if;
        when new.scope_id_or_special = 'descendants' then
          select rgs.scope_id_or_special
            from iam_role_grant_scope rgs
            where rgs.role_id = new.role_id and rgs.scope_id_or_special = 'children'
            into existing_scope_id_or_special;
          if existing_scope_id_or_special is not null then
            raise exception 'invalid to specify both "children" and "descendants" as a grant scope';
          end if;
        else
          select isc.public_id from iam_scope isc where isc.public_id = new.scope_id_or_special into validated_scope_id;
          if validated_scope_id is distinct from new.scope_id_or_special then
            raise exception 'invalid grant scope id';
          end if;
      end case;
      return new;
    end if;

    -- Never allowed, because projects don't have child scopes (and we've
    -- already allowed same-scope-id above)
    if role_scope_type = 'project' then
      raise exception 'invalid to set a grant scope ID to non-same scope_id_or_special when role scope type is project';
    end if;

    -- Ensure that what remains really is org
    if role_scope_type != 'org' then
      raise exception 'unknown scope type';
    end if;
    -- If it's "children" then allow it
    if new.scope_id_or_special = 'children' then
      return new;
    end if;
    -- Make "descendants" an error for orgs
    if new.scope_id_or_special = 'descendants' then
      raise exception 'invalid to specify "descendants" as a grant scope when the role''s scope ID is not "global"';
    end if;

    -- We are now dealing with a bare scope ID and need to ensure that it's a
    -- child project of the role's org scope. Look up the parent scope ID for
    -- the grant scope ID given in the row. Allow iff the grant scope ID's
    -- parent matches the role's scope ID. We know that the role is in an org
    -- scope, so the only acceptable possibility here is that the new scope ID
    -- is a project and its parent scope is this org's.

    -- Ensure it exists
    select isc.public_id from iam_scope isc where isc.public_id = new.scope_id_or_special into validated_scope_id;
    if validated_scope_id is distinct from new.scope_id_or_special then
      raise exception 'invalid grant scope id';
    end if;

    -- Ensure it's a project
    select isc.type from iam_scope isc where isc.public_id = new.scope_id_or_special into new_scope_type;
    if new_scope_type != 'project' then
      raise exception 'expected grant scope id scope type to be project';
    end if;

    -- Ensure that the parent of the project is the role's org scope
    select isc.parent_id from iam_scope isc where isc.public_id = new.scope_id_or_special into parent_scope_id;
    if parent_scope_id != role_scope_id then
      raise exception 'grant scope id is not a child project of the role''s org scope';
    end if;
    
    return new;
  end;
  $$ language plpgsql;
  comment on function role_grant_scope_id_or_special_valid() is
    'function used to ensure grant scope ids are valid';

  create trigger ensure_role_grant_scope_id_or_special_valid before insert or update on iam_role_grant_scope
    for each row execute procedure role_grant_scope_id_or_special_valid();
  
  -- Now perform migrations:

  -- First, copy current grant scope ID values from existing roles to the new
  -- table and set the grant scope ID value on each role to the scope ID
  insert into iam_role_grant_scope(role_id, scope_id_or_special)
    select public_id as role_id, grant_scope_id as scope_id_or_special from iam_role;

  -- Drop the now-unnecessary trigger and function from 0/06_iam
  drop trigger ensure_grant_scope_id_valid on iam_role;
  drop function grant_scope_id_valid;

  -- Remove the column from iam_role
  alter table iam_role drop column grant_scope_id;

commit;
