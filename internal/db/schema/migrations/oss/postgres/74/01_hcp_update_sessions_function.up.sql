-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- replaces function from 70/01_hcp_billing_daily.up.sql
  drop function update_sessions_pending_daily_snapshot;

  create function update_sessions_pending_daily_snapshot()
    returns setof sessions_pending_daily_snapshot
  as $$
  begin

    -- already ran for today
      if (date_trunc('day', now()) - '1 day'::interval) = (select max(snapshot_date) from sessions_pending_daily_snapshot)
    then return;
    end if;

    -- never run before and there are only sessions starting from today
      if (select count(*) from sessions_pending_daily_snapshot) = 0
     and date_trunc('day', now()) = (select min(session_pending_time) from wh_session_accumulating_fact)
    then return query
           insert into sessions_pending_daily_snapshot
             (snapshot_date, sessions_pending_count)
           values
             (date_trunc('day', now()) - '1 day'::interval, 0)
           returning *;
         return;
    end if;

    return query
    with
    daily_counts (day, sessions_pending_count) as (
        select date_trunc('day', session_pending_time), count(*)
          from wh_session_accumulating_fact
         where session_pending_time < date_trunc('day', now()) -- before midnight today
           and session_pending_time >= coalesce((select max(snapshot_date) from sessions_pending_daily_snapshot), '-infinity')
      group by date_trunc('day', session_pending_time)
    ),
    daily_range (day) as (
        select bucket
          from generate_series(
                  coalesce(date_trunc('day', (select max(snapshot_date) from sessions_pending_daily_snapshot) + '1 day'::interval),
                           date_trunc('day', (select min(session_pending_time) from wh_session_accumulating_fact)),
                           date_trunc('day', now()) - '1 day'::interval),
                  now() - '1 day'::interval,
                  '1 day'::interval
               ) as bucket
    ),
    missing (day, sessions_pending_count) as (
           select daily_range.day::timestamp with time zone,
                  coalesce(daily_counts.sessions_pending_count, 0)
             from daily_range
        left join daily_counts on daily_range.day = daily_counts.day
    ),
    final (day, sessions_pending_count) as (
      insert into sessions_pending_daily_snapshot
        (snapshot_date, sessions_pending_count)
      select day::date, sessions_pending_count
        from missing
      returning *
    )
      select day, sessions_pending_count
        from final
      order by day desc;
  end;
  $$ language plpgsql
     set timezone to 'utc';
  comment on function update_sessions_pending_daily_snapshot is
    'update_sessions_pending_daily_snapshot is a function that updates the sessions_pending_daily_snapshot table by '
    'querying the data warehouse and inserting the session pending counts for any days since the max snapshot_date '
    'and yesterday. '
    'update_sessions_pending_daily_snapshot returns the rows inserted or null if no rows are inserted.';

commit;