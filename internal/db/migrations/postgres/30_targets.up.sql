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
    (new.public_id, new.scope_id)
  on conflict (public_id) do nothing;
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
    public_id = old.public_id and
    not exists(
        select count(*) from target_all_subtypes 
        where public_id = old.public_id and scope_id = old.scope_id
    );
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

commit;