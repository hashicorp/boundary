-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(46);

  create function test_get_hours_between(start_time timestamptz, end_time timestamptz) returns int
  as $$
      select count(time)::int
        from generate_series(start_time, end_time, interval '1 hour') as time;
  $$ language sql
     immutable
     returns null on null input;

  create function test_get_hours_between(start_time timestamptz) returns int
  as $$
    select test_get_hours_between(start_time, now());
  $$ language sql
     immutable
     returns null on null input;

  select has_view('hcp_billing_monthly_sessions_all', 'monthly view for hcp billing does not exist');
  select has_view('hcp_billing_monthly_sessions_current_month', 'monthly view for hcp billing does not exist');
  select has_view('hcp_billing_monthly_sessions_last_2_months', 'monthly view for hcp billing does not exist');

  select lives_ok('truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact',
                  'Truncate tables in preparation for testing');

  -- validate the warehouse fact tables are empty
  select is(count(*), 0::bigint, 'wh_session_connection_accumulating_fact is not empty') from wh_session_connection_accumulating_fact;
  select is(count(*), 0::bigint, 'wh_session_accumulating_fact is not empty' ) from wh_session_accumulating_fact;

  -- validate the view returns no rows
  select is(count(*), 0::bigint, 'hcp_billing_monthly_sessions_all should return 0 rows when there are no sessions') from hcp_billing_monthly_sessions_all;
  select is(count(*), 1::bigint, 'hcp_billing_monthly_sessions_current_month should return 1 rows when there are no sessions') from hcp_billing_monthly_sessions_current_month;
  select is(count(*), 2::bigint, 'hcp_billing_monthly_sessions_last_2_months should return 1 rows when there are no sessions') from hcp_billing_monthly_sessions_last_2_months;

  create function test_setup_data(start_time timestamptz, end_time timestamptz) returns int
  as $$
  declare
    insert_count int;
    tmp timestamptz;
  begin
    truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact;

    if start_time = end_time then
      return 0::int;
    end if;

    if start_time > end_time then
      -- swap
      tmp := start_time; start_time := end_time; end_time := tmp;
    end if;

    with
    vars (start_one, start_two) as (
      select date_trunc('hour', start_time),
            (date_trunc('hour', start_time) + interval '1 hour') - interval '1 microsecond'
    ),
    time_series (time) as (
      select generate_series(vars.start_one, end_time, interval '1 hour') as ts
        from vars
      union
      select generate_series(vars.start_two, end_time, interval '1 hour') as ts
        from vars
      order by ts
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

    select count(*) into insert_count
      from wh_session_accumulating_fact;

    return insert_count;
  end;
  $$ language plpgsql;

  create function test_setup_data(start_time timestamptz) returns int
  as $$
  begin
    return test_setup_data(start_time, now());
  end;
  $$ language plpgsql;

  create function test_is_not_same_month(start_time timestamptz, end_time timestamptz) returns boolean
  as $$
  begin
    if date_trunc('month', start_time) != date_trunc('month', end_time) then
      return true;
    end if;
    return false;
  end;
  $$ language plpgsql;

  prepare select_hcp_billing_monthly_sessions_all as
   select *
     from hcp_billing_monthly_sessions_all;

  prepare select_hcp_billing_monthly_sessions_current_month as
   select *
     from hcp_billing_monthly_sessions_current_month;

  prepare select_hcp_billing_monthly_sessions_last_2_months as
   select *
     from hcp_billing_monthly_sessions_last_2_months;

  prepare select_hcp_billing_monthly_sessions_last_2_months_1_row as
   select *
     from hcp_billing_monthly_sessions_last_2_months
    limit 1;

  select is(test_setup_data(now()), 0::int, 'hcp billing: test_setup_data start_time of now() should insert 0 data');
  select is(count(*), 0::bigint, 'hcp_billing_monthly_sessions_all should return 0 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_all;
  select is_empty('select_hcp_billing_monthly_sessions_all', 'hcp_billing_monthly_sessions_all should have no rows when there are no sessions in the warehouse');
  select is(count(*), 1::bigint, 'hcp_billing_monthly_sessions_current_month should return 1 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_current_month;
  select is(count(*), 2::bigint, 'hcp_billing_monthly_sessions_last_2_months should return 2 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_last_2_months;

  select is(test_setup_data(now(), now()), 0::int, 'hcp billing: test_setup_data start_time of now should insert 0 data');
  select is(count(*), 0::bigint, 'hcp_billing_monthly_sessions_all should return 0 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_all;
  select is_empty('select_hcp_billing_monthly_sessions_all', 'hcp_billing_monthly_sessions_all should have no rows when there are no sessions in the warehouse');
  select is(count(*), 1::bigint, 'hcp_billing_monthly_sessions_current_month should return 1 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_current_month;
  select is(count(*), 2::bigint, 'hcp_billing_monthly_sessions_last_2_months should return 2 rows when there no rows in the warehouse') from hcp_billing_monthly_sessions_last_2_months;

  -- only sessions in this hour
  select is(test_setup_data(date_trunc('hour', now())), 1::int,
      'hcp billing: test_setup_data: start_time of this hour should insert 1');
  select is(count(*), 1::bigint,
      'hcp_billing_monthly_sessions_all should return 1 row when there are only sessions in this hour') from hcp_billing_monthly_sessions_all;
  select row_eq('select_hcp_billing_monthly_sessions_all',  row(date_trunc('month', now()), date_trunc('hour', now()), 0::bigint),
      'hcp_billing_monthly_sessions_all should have 1 row with 0 sessions_pending_count when there are only sessions for this hour');
  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_all',
      'hcp_billing_monthly_sessions_current_month and hcp_billing_monthly_sessions_all should be equal');
  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_last_2_months_1_row',
      'hcp_billing_monthly_sessions_current_month and the first row of hcp_billing_monthly_sessions_last_2_months should be equal');

  -- only sessions for yesterday
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 3)
         else collect_tap(
           is(test_setup_data( 'yesterday'::timestamptz, 'today'::timestamptz - interval '1 microsecond' ), 48::int,
                  'hcp billing: test_setup_data: should be 48 sessions for yesterday'),
           row_eq('select_hcp_billing_monthly_sessions_all', row(date_trunc('month', now()), date_trunc('hour', now()), 48::bigint),
                  'hcp_billing_monthly_sessions_all should have 1 row with 48 sessions_pending_count when there are only sessions for yesterday'),
           results_eq( 'select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_all',
                  'hcp_billing_monthly_sessions_current_month and hcp_billing_monthly_sessions_all should be equal')
         )
         end;

  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_last_2_months_1_row',
      'hcp_billing_monthly_sessions_current_month and the first row of hcp_billing_monthly_sessions_last_2_months should be equal');

  -- only sessions for this month
  -- every hour gets 2 sessions
  --    1 at the start of the hour 01:00:00
  --    1 at the end of the hour (start of next hour - 1 microsecond)
  -- the current hour only gets one because the end of the hour has not occurred
  -- every day gets 48 sesions (2 for each hour)
  -- every month gets 48 * number of days in the month
  -- current month gets 48 * number of hours since the start of the month - 1
  -- the current month from the hcp_billing view returns
  --    number of hours from the start of the month until the hour before now * 2
  -- when reporting the current hour is not included in the view
  select is( test_setup_data( date_trunc('month', now()) ),
              -- +1 for the current hour
             (test_get_hours_between( date_trunc('month', now()), now() - interval '1 hour') * 2)::int + 1,
            'hcp billing: test_setup_data: wrong number of sessions for the current month');

  select is(count(*), 1::bigint,
            'hcp_billing_monthly_sessions_all should return 1 row when there are only sessions in this month') from hcp_billing_monthly_sessions_all;

  select row_eq('select_hcp_billing_monthly_sessions_all',
            row( date_trunc('month', now()),
                 date_trunc('hour', now()),
                  -- 2 sessions per hour, the current hour is not included
                 (test_get_hours_between( date_trunc('month', now()), now() - interval  '1 hour') * 2)::bigint
            ),
      'hcp_billing_monthly_sessions_all should have 1 row with 48 sessions_pending_count when there are only sessions for yesterday');

  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_all',
      'hcp_billing_monthly_sessions_current_month and hcp_billing_monthly_sessions_all should be equal');
  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_last_2_months_1_row',
      'hcp_billing_monthly_sessions_current_month and the first row of hcp_billing_monthly_sessions_last_2_months should be equal');

  -- only sessions for this month and last month
  -- same rules as above for the current month
  -- the previous month gets 48 sessions per day * the number of days in the month

  create table test_hcp_billing (
    start_time             timestamptz not null,
    end_time               timestamptz not null,
    sessions_pending_count bigint not null,
    primary key(start_time, end_time)
  );

  prepare insert_2_month_results as
    insert into test_hcp_billing
      (start_time, end_time, sessions_pending_count)
    select date_trunc('month', now()),
           date_trunc('hour', now()),
          (test_get_hours_between( date_trunc('month', now()), now() - interval '1 hour' ) * 2)::bigint
    union
    select date_trunc('month', now() - interval '1 month' ),
           date_trunc('month', now()),
           extract(days from date_trunc('month', now()) - interval '1 day')::int * 48;

  prepare select_test_hcp_billing as
    select * from test_hcp_billing
    order by start_time desc;

  prepare select_hcp_billing_monthly_sessions_all_1_row as
   select *
     from hcp_billing_monthly_sessions_all
    limit 1;

  select lives_ok('insert_2_month_results', 'insert rows into test_hcp_billing');

  select is( test_setup_data( date_trunc('month', now() - interval '1 month' ) ),
            (test_get_hours_between( date_trunc('month', now() - interval '1 month' )) * 2)::int - 1,
            'hcp billing: test_setup_data: wrong number of sessions for 2 months');

  select is(count(*), 2::bigint,
            'hcp_billing_monthly_sessions_all should return 2 rows when there are only sessions for the last 2 months') from hcp_billing_monthly_sessions_all;

  select results_eq('select_hcp_billing_monthly_sessions_all', 'select_test_hcp_billing',
            'hcp_billing_monthly_sessions_all should have 2 rows');

  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_all_1_row',
      'hcp_billing_monthly_sessions_current_month and hcp_billing_monthly_sessions_all should be equal');

  select results_eq('select_hcp_billing_monthly_sessions_all', 'select_hcp_billing_monthly_sessions_last_2_months',
            'hcp_billing_monthly_sessions_all and hcp_billing_monthly_sessions_last_2_months should be equal');
  -- sessions for the last 13 months
  -- same rules as above for the current month
  -- the all previous months get 48 sessions per day * the number of days in the month

  truncate test_hcp_billing;

  prepare insert_13_months_results as
    with
    expected (start_time, end_time, session_count) as (
      select date_trunc('month', time - interval '1 month'),
             date_trunc('month', time),
             extract(days from date_trunc('month', time) - interval '1 day')::bigint * 48
        from generate_series( now() - interval '12 months', now(), '1 month'::interval) as time
      union
      select date_trunc('month', now()),
             date_trunc('hour', now()),
             (test_get_hours_between( date_trunc('month', now()), now() - interval '1 hour' ) * 2)::bigint
    )
    insert into test_hcp_billing
      (start_time, end_time, sessions_pending_count)
    select start_time, end_time, session_count
      from expected;

  prepare select_hcp_billing_monthly_sessions_all_2_rows as
   select *
     from hcp_billing_monthly_sessions_all
    limit 2;

  select lives_ok('insert_13_months_results', 'insert rows into test_hcp_billing');

  select is(count(*), 14::bigint,
            'test_hcp_billing should return 14 rows') from test_hcp_billing;

  select is( test_setup_data( date_trunc('month', now() - interval '13 month' ) ),
            (test_get_hours_between( date_trunc('month', now() - interval '13 month' )) * 2)::int - 1,
            'hcp billing: test_setup_data: wrong number of sessions for 13 months');

  select is(count(*), 14::bigint,
            'hcp_billing_monthly_sessions_all should return 14 rows') from hcp_billing_monthly_sessions_all;

  select results_eq('select_hcp_billing_monthly_sessions_all', 'select_test_hcp_billing',
            'hcp_billing_monthly_sessions_all should have 14 rows');

  select results_eq('select_hcp_billing_monthly_sessions_current_month', 'select_hcp_billing_monthly_sessions_all_1_row',
      'hcp_billing_monthly_sessions_current_month and hcp_billing_monthly_sessions_all should be equal');

  select results_eq('select_hcp_billing_monthly_sessions_all_2_rows', 'select_hcp_billing_monthly_sessions_last_2_months',
            'hcp_billing_monthly_sessions_last_2_months should be equal to the first 2 rows of hcp_billing_monthly_sessions_all');

  select * from finish();

rollback;
