-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(10);

  select has_view('hcp_billing_hourly_sessions_last_3_hours', 'view for hcp billing does not exist');

  select lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact',
                  'Truncate tables in preparation for testing');

  -- validate the warehouse fact tables are empty
  select is(count(*), 0::bigint, 'wh_session_connection_accumulating_fact is not empty') from wh_session_connection_accumulating_fact;
  select is(count(*), 0::bigint, 'wh_session_accumulating_fact is not empty' ) from wh_session_accumulating_fact;

  select is(count(*), 4::bigint, 'hcp_billing_hourly_sessions_last_3_hours should always return 4 rows') from hcp_billing_hourly_sessions_last_3_hours;

  -- insert one session per minute for the past 2 hours
  -- total is 121 = 60 minutes * 2 plus 1 for current minute
  with
  dim_keys (host_key, user_key, credential_group_key) as (
    select h.key, u.key, 'no credentials'
      from (select key from wh_host_dimension limit 1) as h,
           (select key from wh_user_dimension limit 1) as u
  ),
  time_series (date_key, time_key, time) as (
    select wh_date_key(time), wh_time_key(time), time
      from generate_series(
              now() - interval '2 hours',
              now(),
              interval '1 minute'
           ) as time
  ),
  fake_sessions (session_id, auth_token_id,
                 host_key, user_key, credential_group_key,
                 session_pending_date_key, session_pending_time_key, session_pending_time) as (
    select concat('s__________', t.date_key, t.time_key), concat('a__________', t.date_key, t.time_key),
           k.host_key, k.user_key, k.credential_group_key,
           t.date_key, t.time_key,t.time
      from dim_keys as k,
           time_series as t
  )
  insert into wh_session_accumulating_fact
        (session_id, auth_token_id,
         host_key, user_key, credential_group_key,
         session_pending_date_key, session_pending_time_key, session_pending_time
        )
  select session_id, auth_token_id,
         host_key, user_key, credential_group_key,
         session_pending_date_key, session_pending_time_key, session_pending_time
    from fake_sessions;

  select is(count(*), 4::bigint, 'hcp_billing_hourly_sessions_last_3_hours should always return 4 rows') from hcp_billing_hourly_sessions_last_3_hours;

  select results_eq(
    'select count(*)::bigint from wh_session_accumulating_fact',
    'select sum(sessions_pending_count)::bigint from hcp_billing_hourly_sessions_last_3_hours',
    'hcp_billing_hourly_sessions_last_3_hours: the sum of sessions is incorrect'
  );

  select results_eq(
    'select sessions_pending_count::bigint from hcp_billing_hourly_sessions_last_3_hours limit 1',
    'select extract(minute from now())::bigint + 1',
    'hcp_billing_hourly_sessions_last_3_hours: session count for the current hour is incorrect'
  );

  select results_eq(
    'select * from hcp_billing_hourly_sessions_last_3_hours',
    'select * from hcp_billing_hourly_sessions_last_7_days limit 4',
    'hcp_billing_hourly_sessions_last_3_hours and hcp_billing_hourly_sessions_last_7_days: latest 3 hours should be equal'
  );

  select results_eq(
    'select sessions_pending_count::bigint from hcp_billing_hourly_sessions_last_3_hours order by hour limit 1',
    'select 0::bigint',
    'hcp_billing_hourly_sessions_last_3_hours: session count for the last hour is incorrect'
  );

  select * from finish();

rollback;
