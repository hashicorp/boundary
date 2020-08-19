begin;

create or replace function
  kms_scope_valid()
  returns trigger
as $$
declare scope_type text;
begin
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into scope_type;
  -- Always allowed
  if scope_type = 'global' then
    return new;
  end if;
  if scope_type = 'org' then
    return new;
  end if;
  raise exception 'invalid to scope type (must be global or org)';
end;
$$ language plpgsql;

-- kms_version_column() will increment the version column whenever row data
-- is inserted and should only be used in an before insert trigger.  This
-- function will overwrite any explicit values to the version column.
create or replace function
  kms_version_column()
  returns trigger
as $$
declare 
  _key_id text;
  _max bigint; 
begin
  execute format('SELECT $1.%I', tg_argv[0]) into _key_id using new;
  execute format('select max(version) + 1 from %I where %I = $1', tg_relid::regclass, tg_argv[0]) using _key_id into _max;
  if _max is null then
  	_max = 1;
  end if;
  new.version = _max;
  return new;
end;
$$ language plpgsql;

comment on function
  kms_version_column()
is
  'function used in before insert triggers to properly set version columns for kms_* tables with a version column';
  
  commit;