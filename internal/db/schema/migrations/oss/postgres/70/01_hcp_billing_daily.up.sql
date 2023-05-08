-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
drop view if exists hcp_billing_daily_sessions_current_day;
create view hcp_billing_daily_sessions_current_day as
with
    daily_counts (day, sessions_pending_count) as (
        select date_trunc('day', session_pending_time), count(*)
        from wh_session_accumulating_fact
        where session_pending_time >= date_trunc('day', now())
          and session_pending_time < date_trunc('hour', now())
        group by date_trunc('day', session_pending_time)
    ),
    daily_range (day) as (
        select date_trunc('day', now())
    ),
    final (start_time, end_time, sessions_pending_count) as (
        select daily_range.day, -- start
               case when daily_range.day = date_trunc('day', now())
                        then date_trunc('hour', now())
                    else daily_range.day + interval '1 day'
                   end,
               coalesce(daily_counts.sessions_pending_count, 0)
        from daily_range
                 left join daily_counts on daily_range.day = daily_counts.day
    )
select start_time, end_time, sessions_pending_count
from final
order by start_time desc;
comment on view hcp_billing_daily_sessions_current_day is
    'hcp_billing_daily_sessions_current_day is a view that contains '
        'the sum of pending sessions '
        'from the beginning of the current day '
        'until the start of the current hour (exclusive).';

drop view if exists hcp_billing_daily_sessions_all;
create view hcp_billing_daily_sessions_all as
with
    daily_counts (day, sessions_pending_count) as (
        select date_trunc('day', session_pending_time), count(*)
        from wh_session_accumulating_fact
        where session_pending_time < date_trunc('hour', now())
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
    final (start_time, end_time, sessions_pending_count) as (
        -- select daily_range.day - interval '1 day', -- start
        select daily_range.day, -- start
               case when daily_range.day = date_trunc('day', now())
                        then date_trunc('hour', now())
                    else daily_range.day + interval '1 day'
                   end,
               coalesce(daily_counts.sessions_pending_count, 0)
        from daily_range
                 left join daily_counts on daily_range.day = daily_counts.day
    )
select start_time, end_time, sessions_pending_count
from final
order by start_time desc;
comment on view hcp_billing_daily_sessions_all is
    'hcp_billing_daily_sessions_all is a view that contains '
        'the sum of pending sessions for the current month and all previous months. '
        'The current month is a sum from the beginning of the current month '
        'until the start of the current hour (exclusive).';
commit;
