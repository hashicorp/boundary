-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(1);
  
  select results_eq(
    'select count(*)::bigint from get_deletion_tables()',
    'select count(*)::bigint from pg_indexes where schemaname = ''public'' and indexname like tablename || ''_update_time_idx''',
    'every table with a deletion table should also have an index on the update_time column'
  );

  select * from finish();
rollback;
