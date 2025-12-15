-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- make the required schema changes to adopt
-- github.com/hashicorp/go-kms-wrapping/extras/kms/v2 
-- this migration is from:
-- https://github.com/hashicorp/go-kms-wrapping/blob/main/extras/kms/migrations/postgres/01_domain_types.up.sql 

create domain kms_private_id as text not null
check(
  length(trim(value)) > 0
);
comment on domain kms_private_id is
 'standard column for private id';

create domain kms_scope_id as text
check(
  length(trim(value)) > 0
);
comment on domain kms_scope_id is
  'standard column for scope id';

create domain kms_timestamp as timestamp with time zone default current_timestamp;
comment on domain kms_timestamp is
'Standard timestamp for all create_time and update_time columns';

create domain kms_version as bigint default 1 not null
  check(
   value > 0
  );
comment on domain kms_version is
  'standard column for row version';

-- kms_immutable_columns() will make the column names immutable which are passed as
-- parameters when the trigger is created. It raises error code 23601 which is a
-- class 23 integrity constraint violation: immutable column  
create function kms_immutable_columns() returns trigger
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
      raise exception 'immutable column: %.%', tg_table_name, col_name using
        errcode = '23601', 
        schema = tg_table_schema,
        table = tg_table_name,
        column = col_name;
  	end if;
  end loop;
  return new;
end;
$$ language plpgsql;
comment on function kms_immutable_columns() is
  'function used in before update triggers to make columns immutable';

create function kms_default_create_time() returns trigger
as $$
begin
  if new.create_time is distinct from now() then
    new.create_time = now();
  end if;
  return new;
end;
$$ language plpgsql;
comment on function kms_default_create_time() is
  'function used to properly set create_time columns';

create function kms_update_time_column() returns trigger
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
comment on function kms_update_time_column() is
  'function used in before update triggers to properly set update_time columns';

commit;
