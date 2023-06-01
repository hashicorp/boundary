-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(9);

  select lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact',
                  'Truncate tables in preparation for testing');

  -- validate the warehouse fact tables are empty
  select is(count(*), 0::bigint, 'wh_session_connection_accumulating_fact is not empty') from wh_session_connection_accumulating_fact;
  select is(count(*), 0::bigint, 'wh_session_accumulating_fact is not empty' ) from wh_session_accumulating_fact;

  -- validate the view returns no rows
  select is(count(*), 0::bigint, 'hcp_billing_daily_sessions_all should return 0 rows when there are no sessions') from hcp_billing_daily_sessions_all;
  select is(count(*), 1::bigint, 'hcp_billing_daily_sessions_yesterday should return 1 row when there are no sessions') from hcp_billing_daily_sessions_yesterday;

  set time zone 'NZ';

  with time_series (time) as (
    select date_trunc('day', now(), 'utc') - interval '1 minute'
  ),
  dim_keys (host_key, user_key, credential_group_key) as (
    select h.key, u.key, 'no credentials'
      from (select key from wh_host_dimension limit 1) as h,
           (select key from wh_user_dimension limit 1) as u
  ),
  dim_time_series (date_key, time_key, time) as (
    select wh_date_key(time), wh_time_key(time), time
      from time_series
  ),
  fake_sessions (session_id, auth_token_id,
                 host_key, user_key, credential_group_key,
                 session_pending_date_key, session_pending_time_key, session_pending_time) as (
    select concat('s__________', t.date_key, t.time_key), concat('a__________', t.date_key, t.time_key),
           k.host_key, k.user_key, k.credential_group_key,
           t.date_key, t.time_key,t.time
      from dim_keys as k,
           dim_time_series as t
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

  create table test_counts (
    day timestamptz primary key,
    sessions_pending_count bigint not null default 0
  );

  insert into test_counts
         (day, sessions_pending_count)
  select date_trunc('day', now() - '1 day'::interval, 'utc'), 1::bigint;

  prepare select_test_counts as select * from test_counts order by day desc;

  prepare select_func_hcp_billing_daily_sessions_all as select * from hcp_billing_daily_sessions_all();
  prepare select_view_hcp_billing_daily_sessions_all as select * from hcp_billing_daily_sessions_all;

  prepare select_func_hcp_billing_daily_sessions_yesterday as select * from hcp_billing_daily_sessions_yesterday();
  prepare select_view_hcp_billing_daily_sessions_yesterday as select * from hcp_billing_daily_sessions_yesterday;

  select results_eq('select_test_counts', 'select_func_hcp_billing_daily_sessions_all', 'daily sessions all: set time zone before insert: results_eq');
  select results_ne('select_test_counts', 'select_view_hcp_billing_daily_sessions_all', 'daily sessions all: set time zone before insert: results_ne');

  select results_eq('select_test_counts', 'select_func_hcp_billing_daily_sessions_yesterday', 'daily sessions yesterday: set time zone before insert: results_eq');
  select results_ne('select_test_counts', 'select_view_hcp_billing_daily_sessions_yesterday', 'daily sessions yesterday: set time zone before insert: results_ne');

  select * from finish();

rollback;
