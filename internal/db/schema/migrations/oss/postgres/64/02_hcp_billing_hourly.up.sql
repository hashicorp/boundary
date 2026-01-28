-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  drop index if exists wh_session_accumulating_fact_session_pending_time_idx;
  create index wh_session_accumulating_fact_session_pending_time_idx on wh_session_accumulating_fact (session_pending_time);
  analyze wh_session_accumulating_fact;

/*
  Implementation Note 1

  SQL is very flexible. I'm 87% sure there are approximately 1,962 different
  ways to write the queries for each of the views below (plus or minus 2). I
  chose the ones below based on the explain plans for each view after filling
  the wh_session_accumulating_fact table with more than 250,000 rows of test
  data.

  The query I used to populate the test data is at the bottom of this file. If
  you need to alter these views, please generate test data and use the explain
  plan to guide your decisions.
*/

  drop view if exists hcp_billing_hourly_sessions_last_3_hours;
  create view hcp_billing_hourly_sessions_last_3_hours as
  with
  hourly_counts (hour, sessions_pending_count) as (
      select date_trunc('hour', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('hour', now() - '3 hours'::interval)
    group by date_trunc('hour', session_pending_time)
  ),
  hourly_range (hour) as (
      select date_trunc('hour',time)
        from generate_series(now() - '3 hours'::interval, now(), '1 hour'::interval) as time
  ),
  final (hour, sessions_pending_count) as (
      select hourly_range.hour, coalesce(hourly_counts.sessions_pending_count, 0)
        from hourly_range
   left join hourly_counts on hourly_range.hour = hourly_counts.hour
  )
    select hour, sessions_pending_count
      from final
  order by hour desc;
  comment on view hcp_billing_hourly_sessions_last_3_hours is
    'hcp_billing_hourly_sessions_last_3_hours is a view where each row contains the timestamp for an hour and the sum of the pending sessions created in that hour. '
      '4 rows are returned: 1 for the current hour plus 3 for the previous 3 hours. '
      'Rows are sorted by the hour in descending order.';

  drop view if exists hcp_billing_hourly_sessions_last_7_days;
  create view hcp_billing_hourly_sessions_last_7_days as
  with
  hourly_counts (hour, sessions_pending_count) as (
      select date_trunc('hour', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('hour', now() - '7 days'::interval)
    group by date_trunc('hour', session_pending_time)
  ),
  hourly_range (hour) as (
      select date_trunc('hour',time)
        from generate_series(now() - '7 days'::interval, now(), '1 hour'::interval) as time
  ),
  final (hour, sessions_pending_count) as (
      select hourly_range.hour, coalesce(hourly_counts.sessions_pending_count, 0)
        from hourly_range
   left join hourly_counts on hourly_range.hour = hourly_counts.hour
  )
    select hour, sessions_pending_count
      from final
  order by hour desc;
  comment on view hcp_billing_hourly_sessions_last_7_days is
    'hcp_billing_hourly_sessions_last_7_days is a view where each row contains the timestamp for an hour and the sum of the pending sessions created in that hour. '
      '169 rows are returned: 1 for the current hour plus 168 for the previous 7 days. '
      'Rows are sorted by the hour in descending order.';

  -- replaced in 70/02_hcp_billing_hourly.up.sql
  drop view if exists hcp_billing_hourly_sessions_all;
  create view hcp_billing_hourly_sessions_all as
  with
  hourly_counts (hour, sessions_pending_count) as (
      select date_trunc('hour', session_pending_time), count(*)
        from wh_session_accumulating_fact
    group by date_trunc('hour', session_pending_time)
  ),
  hourly_range (hour) as (
      select date_trunc('hour',time)
        from generate_series(
                 (select min(session_pending_time) from wh_session_accumulating_fact),
                 now(),
                 '1 hour'::interval
             ) as time
  ),
  final (hour, sessions_pending_count) as (
      select hourly_range.hour, coalesce(hourly_counts.sessions_pending_count, 0)
        from hourly_range
   left join hourly_counts on hourly_range.hour = hourly_counts.hour
  )
    select hour, sessions_pending_count
      from final
  order by hour desc;
  comment on view hcp_billing_hourly_sessions_all is
    'hcp_billing_hourly_sessions_all is a view where each row contains the timestamp for an hour and the sum of the pending sessions created in that hour. '
      'A row is returned for each hour since the first session was created up to and including the current hour. '
      'Rows are sorted by the hour in descending order.';

/*
  Implementation Note 2: Generating test data

  Step 1: Start and connect to the sqltest docker container (see sqltest/README.md).

    The sqltest container initializes with a few sessions already in the data
    warehouse. These sessions will populate rows in the wh_host_dimension and
    wh_user_dimension tables which will be used in the query below.

  Step 2: Truncate the warehouse fact tables:

      truncate wh_session_connection_accumulating_fact, wh_session_accumulating_fact;

  Step 3: Fill the wh_session_accumulating_fact table with 261961 rows of data:

      with
      dim_keys (host_key, user_key, credential_group_key) as (
        select h.key, u.key, 'no credentials'
          from (select key from wh_host_dimension limit 1) as h,
               (select key from wh_user_dimension limit 1) as u
      ),
      time_series (date_key, time_key, time) as (
        select wh_date_key(time), wh_time_key(time), time
          from generate_series(
                  now() - interval '6 months',
                  now() - interval '2 hours',
                  interval '1 minute'
               ) as time
      ),
      fake_sessions (session_id, auth_token_id,
                     host_key, user_key, credential_group_key,
                     session_pending_date_key, session_pending_time_key, session_pending_time) as (
        select substr(md5(random()::text), 0, 15), substr(md5(random()::text), 0, 15),
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

  Step 4: Collect the execution plan for each view to establish a baseline before making changes:

      explain (analyze, buffers) select * from hcp_billing_hourly_sessions_last_3_hours;
      explain (analyze, buffers) select * from hcp_billing_hourly_sessions_last_7_days;
      explain (analyze, buffers) select * from hcp_billing_hourly_sessions_all;
*/
commit;
