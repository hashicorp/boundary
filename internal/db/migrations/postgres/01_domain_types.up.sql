begin;

create domain wt_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_private_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_private_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_scope_id as text
check(
  length(trim(value)) > 10 or value = 'global'
);
comment on domain wt_scope_id is
'"global" or random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_user_id as text
check(
  length(trim(value)) > 10 or value = 'u_anon' or value = 'u_auth'
);
comment on domain wt_scope_id is
'"u_anon", "u_auth", or random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_role_id as text
check(
  length(trim(value)) > 10 or value = 'r_default'
);
comment on domain wt_scope_id is
'"r_default", or random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

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


create domain wt_version as bigint
default 1 
check(
  value > 0
);
comment on domain wt_version is
'standard column for row version';

-- update_version_column() will increment the version column whenever row data
-- is updated and should only be used in an update after trigger.  This function
-- will overwrite any explicit updates to the version column. 
create or replace function
  update_version_column()
  returns trigger
as $$
begin
  if pg_trigger_depth() = 1 then
    if row(new.*) is distinct from row(old.*) then
      execute format('update %I set version = $1 where public_id = $2', tg_relid::regclass) using old.version+1, new.public_id;
      new.version = old.version + 1;
      return new;
    end if;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  update_version_column()
is
  'function used in after update triggers to properly set version columns';

-- immutable_columns() will make the column names immutable which are passed as
-- parameters when the trigger is created.
create or replace function
  immutable_columns()
  returns trigger
as $$
declare 
	col_name text; 
	new_value text;
	old_value text;
begin
  foreach col_name in array tg_argv loop
    execute format('SELECT $1.%I', col_name) into new_value using new;
    execute format('SELECT $1.%I', col_name) into old_value using old;
  	if new_value is distinct from old_value then
      raise exception 'immutable column: %.%', tg_table_name, col_name;
  	end if;
  end loop;
  return new;
end;
$$ language plpgsql;

comment on function
  update_version_column()
is
  'function used in before update triggers to make columns immutable';

commit;
