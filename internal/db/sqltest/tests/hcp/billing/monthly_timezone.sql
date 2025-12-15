-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(20);

  select lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact',
                  'Truncate tables in preparation for testing');

  -- validate the warehouse fact tables are empty
  select is(count(*), 0::bigint, 'wh_session_connection_accumulating_fact is not empty') from wh_session_connection_accumulating_fact;
  select is(count(*), 0::bigint, 'wh_session_accumulating_fact is not empty' ) from wh_session_accumulating_fact;

  -- validate the view returns no rows
  select is(count(*), 0::bigint, 'hcp_billing_monthly_sessions_all should return 0 rows when there are no sessions') from hcp_billing_monthly_sessions_all;
  select is(count(*), 1::bigint, 'hcp_billing_monthly_sessions_current_month should return 1 rows when there are no sessions') from hcp_billing_monthly_sessions_current_month;
  select results_eq('select sessions_pending_count from hcp_billing_monthly_sessions_current_month',
                     array[0::bigint],
                    'hcp_billing_monthly_sessions_current_month should return 1 row with 0 sessions pending');
  select is(count(*), 2::bigint, 'hcp_billing_monthly_sessions_last_2_months should return 2 rows when there are no sessions') from hcp_billing_monthly_sessions_last_2_months;
  select results_eq('select sessions_pending_count from hcp_billing_monthly_sessions_last_2_months',
                     array[0::bigint, 0::bigint],
                    'hcp_billing_monthly_sessions_last_2_months should return 2 rows each with 0 sessions pending');


  set time zone 'NZ';

  with time_series (time) as (
    select date_trunc('month', now(), 'utc') - interval '1 minute'
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

  create table test_counts_all (
    start_time timestamptz primary key,
    end_time timestamptz,
    sessions_pending_count bigint not null default 0
  );
  create table test_counts_current_month as select * from test_counts_all;

  insert into test_counts_all
         (start_time, end_time, sessions_pending_count)
  select date_trunc('month', now(), 'utc') as start_time, -- this month
         date_trunc('hour', now(), 'utc') as end_time,
         0::bigint
  union
  select date_trunc('month', now() - interval '1 month', 'utc') as start_time, -- last month
         date_trunc('month', now(), 'utc') as end_time,
         1::bigint;

  create table test_counts_last_2_months as select * from test_counts_all;

  insert into test_counts_current_month
         (start_time, end_time, sessions_pending_count)
  select date_trunc('month', now(), 'utc') as start_time, -- this month
         date_trunc('hour', now(), 'utc') as end_time,
         0::bigint;

  -- all
  prepare select_func_hcp_billing_monthly_sessions_all as select * from hcp_billing_monthly_sessions_all();
  prepare select_view_hcp_billing_monthly_sessions_all as select * from hcp_billing_monthly_sessions_all;
  prepare select_test_counts_all as select * from test_counts_all order by start_time desc;

  select results_eq('select_test_counts_all', 'select_func_hcp_billing_monthly_sessions_all', 'set time zone before insert: results_eq');
  select results_ne('select_test_counts_all', 'select_view_hcp_billing_monthly_sessions_all', 'set time zone before insert: results_ne');
  select set_eq('select_test_counts_all', 'select_func_hcp_billing_monthly_sessions_all', 'set time zone before insert: set_eq');
  select set_ne('select_test_counts_all', 'select_view_hcp_billing_monthly_sessions_all', 'set time zone before insert: set_ne');

  -- current month
  prepare select_func_hcp_billing_monthly_sessions_current_month as select * from hcp_billing_monthly_sessions_current_month();
  prepare select_view_hcp_billing_monthly_sessions_current_month as select * from hcp_billing_monthly_sessions_current_month;
  prepare select_test_counts_current_month as select * from test_counts_current_month order by start_time desc;

  select results_eq('select_test_counts_current_month', 'select_func_hcp_billing_monthly_sessions_current_month', 'set time zone before insert: results_eq');
  select results_ne('select_test_counts_current_month', 'select_view_hcp_billing_monthly_sessions_current_month', 'set time zone before insert: results_ne');
  select set_eq('select_test_counts_current_month', 'select_func_hcp_billing_monthly_sessions_current_month', 'set time zone before insert: set_eq');
  select set_ne('select_test_counts_current_month', 'select_view_hcp_billing_monthly_sessions_current_month', 'set time zone before insert: set_ne');

  -- last 2 months
  prepare select_func_hcp_billing_monthly_sessions_last_2_months as select * from hcp_billing_monthly_sessions_last_2_months();
  prepare select_view_hcp_billing_monthly_sessions_last_2_months as select * from hcp_billing_monthly_sessions_last_2_months;
  prepare select_test_counts_last_2_months as select * from test_counts_last_2_months order by start_time desc;

  select results_eq('select_test_counts_last_2_months', 'select_func_hcp_billing_monthly_sessions_last_2_months', 'set time zone before insert: results_eq');
  select results_ne('select_test_counts_last_2_months', 'select_view_hcp_billing_monthly_sessions_last_2_months', 'set time zone before insert: results_ne');
  select set_eq('select_test_counts_last_2_months', 'select_func_hcp_billing_monthly_sessions_last_2_months', 'set time zone before insert: set_eq');
  select set_ne('select_test_counts_last_2_months', 'select_view_hcp_billing_monthly_sessions_last_2_months', 'set time zone before insert: set_ne');

  select * from finish();

rollback;
