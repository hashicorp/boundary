-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  create table sessions_pending_daily_snapshot (
    snapshot_date date primary key,
    sessions_pending_count bigint not null
      constraint sessions_pending_count_must_be_zero_or_positive
        check(sessions_pending_count >= 0)
  );
  comment on table sessions_pending_daily_snapshot is
    'sessions_pending_count is a table where each row contains the count of '
    'sessions pending for snapshot_date for that date.';

  create view hcp_billing_daily_sessions_yesterday as
  with
  daily_counts (day, sessions_pending_count) as (
      select date_trunc('day', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('day', now() - '1 day'::interval)
         and session_pending_time < date_trunc('day', now())
    group by date_trunc('day', session_pending_time)
  ),
  daily_range (day) as (
      select date_trunc('day', now() - '1 day'::interval )
  ),
  final (day, sessions_pending_count) as (
      select daily_range.day, coalesce(daily_counts.sessions_pending_count, 0)
        from daily_range
   left join daily_counts on daily_range.day = daily_counts.day
  )
    select day, sessions_pending_count
      from final
  order by day desc;
  comment on view hcp_billing_daily_sessions_yesterday is
    'hcp_billing_daily_sessions_yesterday is a view that contains '
      'the sum of pending sessions '
      'from the beginning of the previous day '
      'until the start of the current day (exclusive).';

  create view hcp_billing_daily_sessions_all as
  with
  daily_counts (day, sessions_pending_count) as (
      select date_trunc('day', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time < date_trunc('day', now())
    group by date_trunc('day', session_pending_time)
  ),
  daily_range (day) as (
      select bucket
        from generate_series(
                   date_trunc('day', (select min(session_pending_time) from wh_session_accumulating_fact)),
                   now() - '1 day'::interval,
                   '1 day'::interval
               ) as bucket
  ),
  final (day, sessions_pending_count) as (
         select daily_range.day::timestamp with time zone,
                coalesce(daily_counts.sessions_pending_count, 0)
           from daily_range
      left join daily_counts on daily_range.day = daily_counts.day
  )
    select day, sessions_pending_count
      from final
  order by day desc;
  comment on view hcp_billing_daily_sessions_all is
    'hcp_billing_daily_sessions_all is a view that contains '
      'the sum of pending sessions for yesterday and all previous days.';

  create function hcp_billing_daily_sessions_all()
    returns table(day timestamp with time zone, sessions_pending_count bigint)
  as $$
    select * from hcp_billing_daily_sessions_all;
  $$ language sql
     immutable
     parallel safe -- all of the functions called are parallel safe
     strict        -- means the function returns null on null input
     set timezone to 'UTC';
  comment on function hcp_billing_daily_sessions_all is
    'hcp_billing_daily_sessions_all is a function that contains '
    'the sum of pending sessions for all days excluding the current day. '
    'All timestamps returned are in UTC.';

  create function hcp_billing_daily_sessions_yesterday()
    returns table(day timestamp with time zone, sessions_pending_count bigint)
  as $$
    select * from hcp_billing_daily_sessions_yesterday;
  $$ language sql
     immutable
     parallel safe -- all of the functions called are parallel safe
     strict        -- means the function returns null on null input
     set timezone to 'UTC';
  comment on function hcp_billing_daily_sessions_yesterday is
    'hcp_billing_daily_sessions_yesterday is a function that contains '
    'the sum of pending sessions for all days excluding the current day. '
    'All timestamps returned are in UTC.';

commit;
