-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
select plan(9);

select has_view('hcp_billing_daily_sessions_yesterday', 'view for hcp billing does not exist');

select lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact',
                'Truncate tables in preparation for testing');

-- validate the warehouse fact tables are empty
select is(count(*), 0::bigint, 'wh_session_connection_accumulating_fact is not empty') from wh_session_connection_accumulating_fact;
select is(count(*), 0::bigint, 'wh_session_accumulating_fact is not empty' ) from wh_session_accumulating_fact;

select is(count(*), 1::bigint, 'hcp_billing_daily_sessions_yesterday should always return 1 row') from hcp_billing_daily_sessions_yesterday;

-- insert one session per minute from one minute before midnight of yesterday until one minute past midnight today
-- 1442 total sessions
with
    dim_keys (host_key, user_key, credential_group_key) as (
        select h.key, u.key, 'no credentials'
          from (select key from wh_host_dimension limit 1) as h,
               (select key from wh_user_dimension limit 1) as u
    ),
    time_series (date_key, time_key, time) as (
        select wh_date_key(time), wh_time_key(time), time
          from generate_series(
                         timestamp 'yesterday' - interval '1 minute',
                         timestamp 'today' + interval '1 minute',
                         interval '1 minute'
               ) as time
    ),
    fake_sessions (session_id, auth_token_id,
                   host_key, user_key, credential_group_key,
                   session_pending_date_key, session_pending_time_key, session_pending_time) as (
        select concat('s__________', t.date_key, t.time_key), concat('a__________', t.date_key, t.time_key),
               k.host_key, k.user_key, k.credential_group_key,
               t.date_key, t.time_key,t.time
          from dim_keys    as k,
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

select is(count(*), 1::bigint, 'hcp_billing_daily_sessions_yesterday should always return 1 row') from hcp_billing_daily_sessions_yesterday;

select results_eq(
               'select count(*)::bigint from wh_session_accumulating_fact',
               'select sum(sessions_pending_count)::bigint + 3 from hcp_billing_daily_sessions_yesterday',
               'hcp_billing_daily_sessions_yesterday: the sum of sessions is incorrect'
           );

select results_eq(
               'select sessions_pending_count::bigint from hcp_billing_daily_sessions_yesterday limit 1',
               'select 1440::bigint',
               'hcp_billing_daily_sessions_yesterday: session count for the previous day is incorrect'
           );

select results_eq(
               'select * from hcp_billing_daily_sessions_yesterday',
               'select * from hcp_billing_daily_sessions_all limit 1',
               'hcp_billing_daily_sessions_yesterday and hcp_billing_daily_sessions_all: latest day should be equal'
           );

select * from finish();

rollback;
