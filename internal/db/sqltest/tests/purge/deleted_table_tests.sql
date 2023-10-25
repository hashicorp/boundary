-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function op_table(deletion_table_name name) returns text
  as $$
    select split_part(deletion_table_name, '_deleted', 1);
  $$ language sql;

  create function has_operational_table(deletion_table_name name) returns text
  as $$
    select has_table(op_table(deletion_table_name));
  $$ language sql;

  -- tests that the deletion table has the insert trigger
  create function has_insert_trigger(deletion_table_name name) returns text
  as $$
    select * from collect_tap(
      has_trigger(op_table(deletion_table_name), 'insert_deleted_id'),
      trigger_is(op_table(deletion_table_name), 'insert_deleted_id', 'insert_deleted_id')
    );
  $$ language sql;

  -- tests the public_id column
  create function has_public_id(deletion_table_name name) returns text
  as $$
    select * from collect_tap(
      has_column(deletion_table_name, 'public_id'),
      col_not_null(deletion_table_name, 'public_id'),
      col_hasnt_default(deletion_table_name, 'public_id')
    );
  $$ language sql;

  -- tests the delete_time column
  create function has_delete_time(deletion_table_name name) returns text
  as $$
    select * from collect_tap(
      has_column(deletion_table_name, 'delete_time'),
      col_not_null(deletion_table_name, 'delete_time'),
      col_hasnt_default(deletion_table_name, 'delete_time')
    );
  $$ language sql;

  -- tests for delete_time index
  create function has_delete_time_index(deletion_table_name name) returns text
  as $$
    select case when length(deletion_table_name || '_delete_time_idx') > 63
           then hasnt_index(deletion_table_name, deletion_table_name || '_delete_time_idx', 'Index name too long: ' || deletion_table_name || '_delete_time_idx')
           else collect_tap(
                has_index(deletion_table_name, deletion_table_name || '_delete_time_idx', 'delete_time')
              ) end;
  $$ language sql;

  -- tests the tables exist and follow the required naming pattern
  create function has_correct_tables(deletetion_table_name name) returns text
  as $$
    select * from collect_tap(
      has_table(deletetion_table_name),
      has_operational_table(deletetion_table_name)
    );
  $$ language sql;

  -- runs all the tests on a single deletion table
  create function test_deletion_table(deletion_table_name name) returns text
  as $$
    select * from collect_tap(
      has_correct_tables(deletion_table_name),
      has_public_id(deletion_table_name),
      has_delete_time(deletion_table_name),
      has_delete_time_index(deletion_table_name),
      has_insert_trigger(deletion_table_name)
    );
  $$ language sql;

  -- 11 tests for each deletion table
  select plan(a.table_count::integer)
    from (
      select 11 * count(*) as table_count
        from get_deletion_tables()
    ) as a;

    select test_deletion_table(a)
      from get_deletion_tables() a;

  select * from finish();
rollback;
