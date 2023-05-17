-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  create table sessions_pending_daily_snapshot (
    date date primary key,
    sessions_pending_count bigint not null
  );

  create view hcp_billing_daily_sessions_yesterday as
  with
  daily_counts (day, sessions_pending_count) as (
      select date_trunc('day', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('day', timestamp 'yesterday')
         and session_pending_time < date_trunc('day', timestamp 'today')
    group by date_trunc('day', session_pending_time)
  ),
  daily_range (day) as (
      select date_trunc('day', timestamp 'yesterday')
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
       where session_pending_time < date_trunc('day', timestamp 'today')
    group by date_trunc('day', session_pending_time)
  ),
  daily_range (day) as (
      select date_trunc('day', time)
        from generate_series(
                   (select min(session_pending_time) from wh_session_accumulating_fact),
                   now(),
                   '1 day'::interval
             ) as time
  ),
  final (day, sessions_pending_count) as (
         select daily_range.day::timestamp without time zone,
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
commit;
