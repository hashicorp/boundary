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
    -- same-scope-id case above
    if role_scope_type = 'global' then
      return new;
    end if;
    -- Never allowed, because projects don't have child scopes (and we've
    -- already allowed same-scope-id above)
    if role_scope_type = 'project' then
      raise exception 'invalid to set a grant scope ID to non-same scope_id when role scope type is project';
    end if;
    -- Ensure that it really is org
    if role_scope_type != 'org' then
      raise exception 'unknown scope type';
    end if;

    -- If it's "children" then allow it, this will be allowed for global too
    -- above
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

  -- Now perform migrations:

  -- First, copy current grant scope ID values from existing roles to the new
  -- table and set the grant scope ID value on each role to the scope ID
  insert into iam_role_grant_scope(role_id, scope_id)
    select public_id as role_id, grant_scope_id as scope_id from iam_role;
  update iam_role set grant_scope_id=scope_id;

  -- Next, replace the original grant scope id valid function with one that
  -- requires that the grant scope id is not null and is the same as the role
  -- (we will enforce this on the application side too)
  -- Replaces function from 0/06_iam
  create or replace function grant_scope_id_valid() returns trigger
  as $$
  begin
    new.grant_scope_id = new.scope_id;
    return new;
  end;
  $$ language plpgsql;

  -- Finally, set that field immutable
  drop trigger a_immutable_columns on iam_role;
  -- Replaces trigger from 0/06_iam. Note that we have changed this to
  -- b_immutable_columns, so that we can have the forcing function for
  -- overriding grant scope id (below) run first to not fall afoul of this.
  create trigger b_immutable_columns before update on iam_role
    for each row execute procedure immutable_columns('public_id', 'create_time', 'scope_id', 'grant_scope_id');


  -- Provide an easy path for allowing existing update logic but no longer
  -- applying to the immutable column, which we do by just forcing the value on
  -- any update.
  create or replace function override_iam_role_grant_scope_id() returns trigger
  as $$
  begin
    new.grant_scope_id = old.grant_scope_id;
    return new;
  end;
  $$ language plpgsql;

  -- The trigger to run this is named to come before the immutable columns check
  create trigger a_override_role_grant_scope_id_update before insert or update on iam_role
    for each row execute procedure override_iam_role_grant_scope_id();

commit;