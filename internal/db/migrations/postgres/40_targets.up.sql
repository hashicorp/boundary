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
  target_host_set_scope_valid_orig()
  returns trigger
as $$
declare hc_scope_id text;
declare t_scope_id text;
declare scope_type text;
begin
  select 
    hc.scpoe_id,
    t.scope_id,
    s.type
  from 
    scope s,
    host_set hs,
    host_catalog hc,
    target t
  where 
    hs.catalog_id = hc.public_id and
    hc.scope_id = s.scope_id and 
    hs.public_id = new.host_set_id and 
    t.public_id = new.target_id 
  into hc_scope_id, t_scope_id;
  -- Always allowed
  if hc_scope_id != t_scope_id then
    raise exception 'host set scope % and target scope % are not equal', hc_scope_id, t_scope_id;
  end if;
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
declare hs_scope_id text;
declare hs_scope_type text;
declare hs_scope_parent_id text;
declare t_scope_id text;
declare t_scope_type text;
declare t_scope_parent_id text;
begin
  select 
    hc.scope_id,
    s.parent_id,
    s.type
  from 
    scope s,
    host_set hs,
    host_catalog hc
  where 
    hs.catalog_id = hc.public_id and
    hc.scope_id = s.scope_id and 
    hs.public_id = new.host_set_id
  into hs_scope_id, hs_scope_type, hs_scope_parent_id;

  select 
    s.public_id,
    s.type,
    s.parent_id
  from 
    scope s,
    target t
  where 
    s.public_id = new.target_id 
  into t_scope_id, t_scope_type, t_scope_parent_id;
  
  if hs_scope_id == t_scope_id then
    if hs_scope_type = 'org' then
      return new;
    end if;
    if hs_scope_type = 'project' then
      return new;
    end if;
    raise exception 'scopes (% == %) match but invalid scope type % (must be org or project)', hs_scope_id, t_scope_id, scope_type;
  end if;

  if t_scope_type = 'org' then
    -- Allow if target scope is the parent of the host set; this is, if the host
    -- set belongs to a direct child scope of the target's org 
    if t_scope_id = hs_scope_parent_id then
      return new;
    end if;
    raise exception 'host set scope % is not a child project of the target scope %', hs_scope_id, t_scope_id;
  end if;

  if hs_scope_type = 'org' then
    -- Allow if host set scope is the parent of the target; this is, if the
    -- target belongs to a direct child scope of the host set's org  
    if hs_scope_id = t_scope_parent_id then
      return new;
    end if;
    raise exception 'target scope % is not a child project of the host set scope %', t_scope_id, hs_scope_id;
  end if;

  -- well, it's not a valid scope relationship
  raise exception 'target scope % and host set scope % are not equal and not related via an org', t_scope_id, hs_scope_id;
end;
$$ language plpgsql;


commit;