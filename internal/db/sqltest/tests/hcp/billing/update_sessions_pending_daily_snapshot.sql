-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(38);

  select has_function('update_sessions_pending_daily_snapshot');
  select volatility_is('update_sessions_pending_daily_snapshot', 'volatile');
  select isnt_strict('update_sessions_pending_daily_snapshot');

  prepare call_update_sessions_pending_daily_snapshot
    as select * from update_sessions_pending_daily_snapshot();

  create function test_add_session(ts timestamptz) returns void
  as $$
    with time_series (time) as (
      select ts
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
  $$ language sql;

  create function today() returns timestamptz
  as $$
    select date_trunc('day', now(), 'utc');
  $$ language sql;

  create function yesterday() returns timestamptz
  as $$
    select today() - '1 day'::interval;
  $$ language sql;

  create function has_empty_table(table_name name) returns text
  as $$
  declare
    result text;
  begin
    execute format('select is(count(*), 0::bigint) from %I', table_name) into result;
    return result;
  end;
  $$ language plpgsql;

  create table test_table_data (
    snapshot_date date primary key,
    sessions_pending_count bigint not null
  );
  prepare select_test_table_data as select * from test_table_data order by snapshot_date desc;

  -- add 5 to plan every time this is called
  create function reset_data() returns text
  as $$
    select * from collect_tap(
      lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact, sessions_pending_daily_snapshot, test_table_data'),
      has_empty_table('wh_session_connection_accumulating_fact'),
      has_empty_table('wh_session_accumulating_fact'),
      has_empty_table('sessions_pending_daily_snapshot'),
      has_empty_table('test_table_data')
    );
  $$ language sql;

  -- new install, no sessions
  select reset_data();
  -- no sessions
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date, 0;
  select results_eq('call_update_sessions_pending_daily_snapshot', 'select_test_table_data');
  select is(t.*, null, 'update_sessions_pending_daily_snapshot should return null when it has already been run for the day') from update_sessions_pending_daily_snapshot() as t;

  -- new install, only sessions are for today
  select reset_data();
  select test_add_session(today());
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date, 0;
  select results_eq('call_update_sessions_pending_daily_snapshot', 'select_test_table_data');

  -- upgrade install, sessions are for today and yesterday
  select reset_data();
  select test_add_session(yesterday());
  select test_add_session(today());
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date, 1;
  select results_eq('call_update_sessions_pending_daily_snapshot', 'select_test_table_data');

  -- upgrade install, sessions are for today, yesterday, and 2 days ago
  select reset_data();
  select test_add_session(yesterday() - '1 day'::interval);
  select test_add_session(yesterday());
  select test_add_session(today());
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date - '1 day'::interval, 1;
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date, 1;
  select results_eq('call_update_sessions_pending_daily_snapshot', 'select_test_table_data');

  -- upgrade install, add session for 2 days ago, do not add a session for yesterday
  -- add row to real sessions_pending table, as update_sessions_pending_daily_snapshot fn needs to read from it if missing data from yesterday
  select reset_data();
  select test_add_session(yesterday() - '1 day'::interval);
  insert into sessions_pending_daily_snapshot (snapshot_date, sessions_pending_count) select yesterday()::date - '1 day'::interval, 1;
  insert into test_table_data (snapshot_date, sessions_pending_count) select yesterday()::date, 0;
  select results_eq('call_update_sessions_pending_daily_snapshot', 'select_test_table_data');

  select reset_data();
  select * from finish();
rollback;
