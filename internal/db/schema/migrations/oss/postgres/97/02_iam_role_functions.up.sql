  -- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  
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

  create function delete_iam_role_subtype() returns trigger
  as $$
  begin
    delete
      from iam_role
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
    $$ language plpgsql;
    comment on function delete_iam_role_subtype() is
      'delete_iam_role_subtype is used to automatically delete associated iam_role entry'
      'since domain implementation performs deletion on the child table which does not cleanup the base iam_role table ';

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

  -- set_resource sets the resource column based on the "type" token in the canonical_grant.
  create function set_resource() returns trigger
  as $$
  declare type_matches text[];
  begin
    -- Extract all "type" tokens from the canonical_grant string
    with
    parts (p) as (
      select p
        from regexp_split_to_table(new.canonical_grant, ';') as p
    ),
    kv (k, v) as (
    select part[1] as k,
      part[2] as v
    from parts,
      regexp_split_to_array(parts.p, '=') as part
    )
    select array_agg(v)
      into type_matches
    from kv
    where k = 'type';
    -- if there are multiple canonical grant types specified, throw an error.
    -- Ensure that the canonical_grant type is only referencing a single resource
    if type_matches is not null and array_length(type_matches, 1) > 1 then
      raise exception 'multiple type tokens in grant. only one type expected: %', new.canonical_grant;
    elsif type_matches is not null and array_length(type_matches, 1) = 1 then
      new.resource := type_matches[1];
    else
      new.resource := 'unknown';
    end if;
    return new;
  end
  $$ language plpgsql;
  comment on function set_resource() is
    'set_resource sets the resource column based on the "type" token. A valid grant without a type token results in resource being set to "unknown".';

  create function upsert_canonical_grant() returns trigger
  as $$
  begin
    insert into iam_grant
      (canonical_grant)
    values
      (new.canonical_grant)
    on conflict do nothing;
    return new;
  end
  $$ language plpgsql;
  comment on function upsert_canonical_grant() is
    'upsert_canonical_grant is a trigger function that inserts a row into the iam_grant table if the canonical_grant does not exist.';

commit;