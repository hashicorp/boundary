-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  select plan(5);

  select has_table('sessions_pending_daily_snapshot');

  update wh_session_accumulating_fact
     set session_pending_time = session_pending_time - interval '2 day'
   where auth_token_id = 'tok____clare';

  select is(count(*), 2::bigint, 'update_sessions_pending_daily_snapshot() should initially return 2 rows') from update_sessions_pending_daily_snapshot();
  select is(count(*), 0::bigint, 'update_sessions_pending_daily_snapshot() should subsequently return 0 rows') from update_sessions_pending_daily_snapshot();

  -- delete yesterday's record
  delete from sessions_pending_daily_snapshot
        where snapshot_date = date_trunc('day', now() - '1 day'::interval);

  select is(count(*), 1::bigint, 'sessions_pending_daily_snapshot should only have 1 row') from sessions_pending_daily_snapshot;
  select is(count(*), 1::bigint, 'update_sessions_pending_daily_snapshot() should now return 1 row') from update_sessions_pending_daily_snapshot();

rollback;
