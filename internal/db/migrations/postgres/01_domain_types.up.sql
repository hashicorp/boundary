begin;

create domain wt_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_timestamp as
  timestamp with time zone
  default current_timestamp;
comment on domain wt_timestamp is
'Standard timestamp for all create_time and update_time columns';


create or replace function
  update_time_column()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    new.update_time = now();
    return new;
  else
    return old;
  end if;
end;
$$ language plpgsql;

comment on function
  update_time_column()
is
  'function used in before update triggers to properly set update_time columns';

create or replace function
  immutable_create_time_func()
  returns trigger
as $$
begin
  if new.create_time is distinct from old.create_time then
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = old.create_time;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  immutable_create_time_func()
is
  'function used in before update triggers to make create_time column immutable';
  
create or replace function
  default_create_time()
  returns trigger
as $$
begin
  if new.create_time is distinct from now() then
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = now();
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  default_create_time()
is
  'function used in before insert triggers to set create_time column to now';

-- rand_version_string(length) will create a new random version string.  The
-- returned string will be lower cased characters and integers.
create or replace function rand_version_string(length integer)
returns text
language plpgsql
as $$
declare 
 	char_set text := '0123456789abcdefghijklmnopqrstuvqxyz';
	set_size integer := length(char_set);
	result text;
begin
	select array_to_string(
		array(
			select substr(char_set, round(random() * set_size)::integer, 1)
			from generate_series(1, length)
		),
		'') into result;
	return result;
end;
$$;

-- update_version_column() will increment the version column whenever row data
-- is updated and should only be used in an update after trigger.  This function
-- will overwrite any explicit updates to the version column. 
create or replace function
  update_version_column()
  returns trigger
as $$
declare 
 	new_version text := rand_version_string(20);
begin
  if pg_trigger_depth() = 1 then
    if row(new.*) is distinct from row(old.*) then
      execute format('update %I set version = $1 where public_id = $2', tg_relid::regclass) using new_version, new.public_id;
      new.version = new_version;
      return new;
    end if;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  update_time_column()
is
  'function used in after update triggers to properly set version columns';

commit;
