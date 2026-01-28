-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  drop view if exists hcp_billing_monthly_sessions_current_month;
  create view hcp_billing_monthly_sessions_current_month as
  with
  monthly_counts (month, sessions_pending_count) as (
      select date_trunc('month', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('month', now())
         and session_pending_time < date_trunc('hour', now())
    group by date_trunc('month', session_pending_time)
  ),
  monthly_range (month) as (
      select date_trunc('month',now())
  ),
  final (start_time, end_time, sessions_pending_count) as (
      select monthly_range.month, -- start
             case when monthly_range.month = date_trunc('month', now())
                    then date_trunc('hour', now())
                  else monthly_range.month + interval '1 month'
             end,
             coalesce(monthly_counts.sessions_pending_count, 0)
        from monthly_range
   left join monthly_counts on monthly_range.month = monthly_counts.month
  )
    select start_time, end_time, sessions_pending_count
      from final
  order by start_time desc;
  comment on view hcp_billing_monthly_sessions_current_month is
    'hcp_billing_monthly_sessions_current_month is a view that contains '
    'the sum of pending sessions '
    'from the beginning of the current month '
    'until the start of the current hour (exclusive).';

  drop view if exists hcp_billing_monthly_sessions_last_2_months;
  create view hcp_billing_monthly_sessions_last_2_months as
  with
  monthly_counts (month, sessions_pending_count) as (
      select date_trunc('month', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time >= date_trunc('month', now() - interval '1 month')
         and session_pending_time < date_trunc('hour', now())
    group by date_trunc('month', session_pending_time)
  ),
  monthly_range (month) as (
      select date_trunc('month', time)
        from generate_series(
                 date_trunc('month', now() - interval '1 month'),
                 now(),
                 '1 month'::interval
             ) as time
  ),
  final (start_time, end_time, sessions_pending_count) as (
      select monthly_range.month, -- start
             case when monthly_range.month = date_trunc('month', now())
                    then date_trunc('hour', now())
                  else monthly_range.month + interval '1 month'
             end,
             coalesce(monthly_counts.sessions_pending_count, 0)
        from monthly_range
   left join monthly_counts on monthly_range.month = monthly_counts.month
  )
    select start_time, end_time, sessions_pending_count
      from final
  order by start_time desc;
  comment on view hcp_billing_monthly_sessions_last_2_months is
    'hcp_billing_monthly_sessions_last_2_months is a view that contains '
    'the sum of pending sessions for the current month and the previous month. '
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).';

  -- replaced in 70/03_hcp_billing_monthly.up.sql
  drop view if exists hcp_billing_monthly_sessions_all;
  create view hcp_billing_monthly_sessions_all as
  with
  monthly_counts (month, sessions_pending_count) as (
      select date_trunc('month', session_pending_time), count(*)
        from wh_session_accumulating_fact
       where session_pending_time < date_trunc('hour', now())
    group by date_trunc('month', session_pending_time)
  ),
  monthly_range (month) as (
      select date_trunc('month',time)
        from generate_series(
                 (select min(session_pending_time) from wh_session_accumulating_fact),
                 now(),
                 '1 month'::interval
             ) as time
  ),
  final (start_time, end_time, sessions_pending_count) as (
      -- select monthly_range.month - interval '1 month', -- start
      select monthly_range.month, -- start
             case when monthly_range.month = date_trunc('month', now())
                    then date_trunc('hour', now())
                  else monthly_range.month + interval '1 month'
             end,
             coalesce(monthly_counts.sessions_pending_count, 0)
        from monthly_range
   left join monthly_counts on monthly_range.month = monthly_counts.month
  )
    select start_time, end_time, sessions_pending_count
      from final
  order by start_time desc;
  comment on view hcp_billing_monthly_sessions_all is
    'hcp_billing_monthly_sessions_all is a view that contains '
    'the sum of pending sessions for the current month and all previous months. '
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).';

commit;
