-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- insert_target_subtype() is a before insert trigger
-- function for subtypes of target
-- Replaced in 44/03_targets.up.sql
create or replace function insert_target_subtype() returns trigger
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
create or replace function delete_target_subtype() returns trigger
as $$
begin
  delete from target
  where 
    public_id = old.public_id;
  return null; -- result is ignored since this is an after trigger
end;
$$ language plpgsql;

-- target_scope_valid() is a before insert trigger function for target
-- Replaced in 44/03_targets.up.sql
create or replace function target_scope_valid() returns trigger
as $$
declare scope_type text;
begin
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into scope_type;
  if scope_type = 'project' then
    return new;
  end if;
  raise exception 'invalid target scope type % (must be project)', scope_type;
end;
$$ language plpgsql;

-- target_host_set_scope_valid() is a before insert trigger function for target_host_set 
-- Replaced in 44/02_hosts.up.sql
create or replace function target_host_set_scope_valid() returns trigger
as $$
begin
    perform from
      host_catalog hc,
      host_set hs,
      target t,
      iam_scope s
    where
      hc.public_id = hs.catalog_id and 
      hc.scope_id = t.scope_id and
      t.public_id = new.target_id;
if not found then
  raise exception 'target scope and host set scope are not equal';
end if;
return new;
end;
$$ language plpgsql;

commit;
