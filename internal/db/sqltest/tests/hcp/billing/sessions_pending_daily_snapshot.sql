-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  insert into sessions_pending_daily_snapshot
  (snapshot_date, sessions_pending_count)
  values
      (timestamp 'yesterday', 100),
      (timestamp 'yesterday' - interval '1 day', 2000);

  select is(count(*), 1::bigint) from sessions_pending_daily_snapshot where snapshot_date = timestamp 'yesterday';
  select is(count(*), 1::bigint) from sessions_pending_daily_snapshot where snapshot_date = timestamp 'yesterday' - interval '1 day';
  select results_eq(
               'select sessions_pending_count::bigint from sessions_pending_daily_snapshot limit 1',
               'select 100::bigint',
               'sessions_pending_daily_snapshot: session count for yesterday day is incorrect'
           );

  select results_eq(
               'select sum(sessions_pending_count)::bigint from sessions_pending_daily_snapshot',
               'select 2100::bigint',
               'sessions_pending_daily_snapshot sum of sessions is incorrect'
           );

  select * from finish();
rollback;
