-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(5);

  select has_function('cleanup_deleted_tables');
  select volatility_is('cleanup_deleted_tables', 'volatile');
  select isnt_strict('cleanup_deleted_tables');

  -- load two sessions into the db, one with a date 30 days ago that should get cleaned
  insert into session_deleted (public_id, delete_time) select 'p1234567890', now()::date;
  insert into session_deleted (public_id, delete_time) select 'p9876543210', now()::date - '30 days'::interval;

  -- ensure the two sessions exist
  select is(count(*), 2::bigint) from session_deleted;

  -- clean up the 30 day old session, ensure session p1234567890 still exists
  select cleanup_deleted_tables();
  select is(count(*), 1::bigint) from session_deleted;

  select * from finish();
rollback;