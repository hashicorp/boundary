-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function set_once_columns() returns trigger
  as $$
  declare 
    col_name text; 
    new_value text;
    old_value text;
  begin
    foreach col_name in array tg_argv loop
      execute format('SELECT $1.%I', col_name) into new_value using new;
      execute format('SELECT $1.%I', col_name) into old_value using old;
      if old_value is not null and new_value is distinct from old_value then
        raise exception 'set_once_violation: %.%', tg_table_name, col_name using
          errcode = '23602', 
          schema = tg_table_schema,
          table = tg_table_name,
          column = col_name;
      end if;
    end loop;
    return new;
  end;
  $$ language plpgsql;
  comment on function set_once_columns() is
    'set_once_columns asserts that a column cannot be updated after being set to a non-null value';

commit;
