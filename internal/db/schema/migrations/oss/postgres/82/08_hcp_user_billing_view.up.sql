-- Copyright (c) HashiCorp, Inc.
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
commit;
