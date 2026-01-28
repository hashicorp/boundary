-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create view hcp_billing_monthly_active_users_last_2_months as
  with
  monthly_range (month) as (
      select date_trunc('month', time) as month
        from generate_series(
                 date_trunc('month', now() - interval '1 month'),
                 now(),
                 '1 month'::interval
             ) as time
  ),
  final (start_time, end_time, active_users_count) as (
      select monthly_range.month, -- start
             case when monthly_range.month = date_trunc('month', now())
                    then date_trunc('hour', now())
                  else monthly_range.month + interval '1 month'
             end,
             count(distinct(user_id))
        from monthly_range
   left join wh_auth_token_accumulating_fact as wh_ataf
          on wh_ataf.auth_token_approximate_active_time_range && tstzrange(monthly_range.month, monthly_range.month + interval '1 month', '[)')
    group by monthly_range.month
  )
    select start_time, end_time, active_users_count
      from final
  order by start_time desc;
  comment on view hcp_billing_monthly_active_users_last_2_months is
    'hcp_billing_monthly_active_users_last_2_months is a view that contains '
    'the count of active users for the current month and the previous month. '
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).';

  create view hcp_billing_monthly_active_users_all as
  with
  monthly_range (month) as (
      select date_trunc('month', time) as month
        from generate_series(
                 date_trunc('month', (select min(auth_token_issued_time)
                                        from wh_auth_token_accumulating_fact)),
                 now(),
                 '1 month'::interval
             ) as time
  ),
  final (start_time, end_time, active_users_count) as (
      select monthly_range.month, -- start
             case when monthly_range.month = date_trunc('month', now())
                    then date_trunc('hour', now())
                  else monthly_range.month + interval '1 month'
             end,
             count(distinct(user_id))
        from monthly_range
   left join wh_auth_token_accumulating_fact as wh_ataf
          on wh_ataf.auth_token_approximate_active_time_range && tstzrange(monthly_range.month, monthly_range.month + interval '1 month', '[)')
    group by monthly_range.month
  )
    select start_time, end_time, active_users_count
      from final
  order by start_time desc;
  comment on view hcp_billing_monthly_active_users_all is
    'hcp_billing_monthly_active_users_all is a view that contains '
    'the count of active users for the all months.'
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).';

  create function hcp_billing_monthly_active_users_last_2_months()
    returns table(start_time timestamp with time zone, end_time timestamp with time zone, active_user_count bigint)
  as $$
    select *
      from hcp_billing_monthly_active_users_last_2_months;
  $$ language sql
     immutable
     parallel safe -- all of the functions called are parallel safe
     strict        -- means the function returns null on null input
     set timezone to 'utc';
  comment on function hcp_billing_monthly_active_users_last_2_months is
    'hcp_billing_monthly_active_users_last_2_months is a function that contains '
    'the count of active users for the current month and the previous month. '
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).'
    'All timestamps returned are in UTC.';

  create function hcp_billing_monthly_active_users_all(p_start_time timestamptz default null,
                                                       p_end_time   timestamptz default null)
    returns setof hcp_billing_monthly_active_users_all
  as $$
  begin
    case
    when p_start_time is not null and p_end_time is not null then
      return query select *
                     from hcp_billing_monthly_active_users_all
                    where start_time >= p_start_time
                      and end_time   <= p_end_time;
    when p_start_time is not null then
      return query select *
                     from hcp_billing_monthly_active_users_all
                    where start_time >= p_start_time;
    when p_end_time is not null then
      return query select *
                     from hcp_billing_monthly_active_users_all
                    where end_time <= p_end_time;
    else
      return query select *
                     from hcp_billing_monthly_active_users_all;
    end case;
    return;
  end;
  $$ language plpgsql
     immutable
     parallel safe -- all of the functions called are parallel safe
     set timezone to 'utc';
  comment on function hcp_billing_monthly_active_users_all is
    'hcp_billing_monthly_active_users_all is a function that contains '
    'the count of active users for the all months.'
    'The current month is a sum from the beginning of the current month '
    'until the start of the current hour (exclusive).'
    'It can be provided with a start time and end time to restrict the results.'
    'All timestamps returned are in UTC.';
commit;
