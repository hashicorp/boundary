begin;

create or replace function
  target_scope_valid()
  returns trigger
as $$
declare scope_type text;
begin
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into scope_type;
  -- Always allowed
  if scope_type = 'org' then
    return new;
  end if;
  if scope_type = 'project' then
    return new;
  end if;
  raise exception 'invalid to scope type (must be org or project)';
end;
$$ language plpgsql;

commit;