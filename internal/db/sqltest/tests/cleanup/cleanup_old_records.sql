-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(4);

  select has_function('cleanup_deleted_tables');
  select volatility_is('cleanup_deleted_tables', 'volatile');
  select isnt_strict('cleanup_deleted_tables');

  insert into session_deleted (public_id, delete_time) select 'p1234567890', now()::date;
  insert into session_deleted (public_id, delete_time) select 'p9876543210', now()::date - '30 days'::interval;

  select * from cleanup_deleted_tables();

  select is(count(*), 1::bigint) from session_deleted;

  select * from finish();
rollback;