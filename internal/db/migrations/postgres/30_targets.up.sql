begin;

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