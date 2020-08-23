begin;


-- insert_target_subtype() is a before insert trigger
-- function for subtypes of target
create or replace function
  insert_target_subtype()
  returns trigger
as $$
begin
  insert into target
    (public_id, scope_id)
  values
    (new.public_id, new.scope_id);
  return new;
end;
$$ language plpgsql;

-- delete_target_subtype() is an after delete trigger
-- function for subtypes of host
create or replace function delete_target_subtype()
  returns trigger
as $$
begin
  delete from target
  where 
    public_id = old.public_id;
  return null; -- result is ignored since this is an after trigger
end;
$$ language plpgsql;

-- target_scope_valid() is a before insert trigger function for target
create or replace function
  target_scope_valid()
  returns trigger
as $$
declare scope_type text;
begin
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into scope_type;
  if scope_type = 'org' then
    return new;
  end if;
  if scope_type = 'project' then
    return new;
  end if;
  raise exception 'invalid to scope type % (must be org or project)', scope_type;
end;
$$ language plpgsql;

-- target_host_set_scope_valid() is a before insert trigger function for target_host_set 
create or replace function
  target_host_set_scope_valid()
  returns trigger
as $$
begin
perform (
  with recursive
  -- using the new.target_id: build a list of valid_scopes that contains the
  -- scope_ids for the org of the target + all of the projects within that org
  valid_scopes(scope_id) as (
    select case s.type  
      when 'org' then s.public_id
      else s.parent_id
      end
    from 
      iam_scope s,
      target t
    where 
      s.public_id = t.scope_id and
      t.public_id = new.target_id 
    union all 
      select s.public_id
      from 
        iam_scope s,
        valid_scopes vs
      where s.parent_id = vs.scope_id        
  ),
  -- using the new.host_set_id: check to see if the scope of the host set's
  -- catalog matches one of the valid_scopes
  final (scope_id) as (
    select hc.scope_id
    from 
      host_catalog hc,
      host_set hs,
      valid_scopes vs
    where
      hc.public_id = hs.catalog_id and 
      hc.scope_id in (vs.scope_id) and 
      hs.public_id = new.host_set_id
  )
  select scope_id from final
);

if not found then
  -- well, it's not a valid scope relationship
  raise exception 'target scope % and host set scope % are not equal and not related via an org', t_scope_id, hs_scope_id;
end if;
return new;
end;
$$ language plpgsql;

commit;