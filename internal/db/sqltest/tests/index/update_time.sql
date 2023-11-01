-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(1);

  select is(count(*), 32::bigint) from pg_indexes where schemaname = 'public' and indexname like tablename || '_update_time_ix';

  select * from finish();
rollback;
