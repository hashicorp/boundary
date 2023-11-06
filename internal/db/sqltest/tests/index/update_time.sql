-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function op_table(deletion_table_name name) returns text
  as $$
    select split_part(deletion_table_name, '_deleted', 1);
  $$ language sql;
  
  create function has_update_time_index(table_name name) returns text
  as $$
    select * from collect_tap(
      has_index(table_name, table_name || '_update_time_idx', 'update_time')
    );
  $$ language sql;

  -- the op table for each deletion table should be tested for the inded
  select plan(a.table_count::integer)
    from (
      select count(*) as table_count
        from get_deletion_tables()
    ) as a;

  select has_update_time_index(op_table(a))
    from get_deletion_tables() a;

  select * from finish();
rollback;
