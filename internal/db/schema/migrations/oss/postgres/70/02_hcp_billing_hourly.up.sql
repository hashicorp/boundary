-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- replaces view from 64/02_hcp_billing_hourly.up.sql
  drop view hcp_billing_hourly_sessions_all;
  create view hcp_billing_hourly_sessions_all as
  with
  hourly_counts (hour, sessions_pending_count) as (
      select date_trunc('hour', session_pending_time), count(*)
        from wh_session_accumulating_fact
    group by date_trunc('hour', session_pending_time)
  ),
  hourly_range (hour) as (
      select bucket
        from generate_series(
               date_trunc('hour', ( select min(session_pending_time) from wh_session_accumulating_fact ) ),
               now(),
               '1 hour'::interval
           ) as bucket
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

commit;
