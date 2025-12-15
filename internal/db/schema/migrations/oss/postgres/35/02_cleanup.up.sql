-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- This adds additional cleanup to what went into 0.8.x. There could be a case
-- where sessions can persist in canceled state even if there are no connections
-- for that session (possibly due to cleanup) and will never be transitioned
-- because connection state cannot be determined.
--
-- If they have previously been marked terminated in the warehouse we delete
-- them; if not we mark them terminated so it's recorded in the warehouse and
-- the cleanup job should eventually clear these out.
with
  canceling_sessions(session_id) as (
    select session_id
      from session_state
     where state = 'canceling'
       and end_time is null
  ),
  no_connection_canceling_sessions as (
    select session_id
      from canceling_sessions
     where session_id not in
             (
               select session_id
                 from session_connection
             )
  ),
  has_termination_reason (session_id) as (
        select public_id
          from session
         where public_id in
                 (
                   select session_id
                     from no_connection_canceling_sessions
                 )
           and termination_reason is not null
  ),
  terminated_in_warehouse (session_id) as (
        select session_id
          from has_termination_reason
         where session_id in
                (
                  select session_id
                    from wh_session_accumulating_fact
                   where session_terminated_date_key <> -1
                )
  ),
  not_terminated_in_warehouse (session_id) as (
        select session_id
          from has_termination_reason
         where session_id not in
                 (
                   select session_id
                     from terminated_in_warehouse
                 )
  ),
  delete_terminated_in_warehouse_from_session as (
        delete from session
         where public_id in
                 (
                   select session_id
                     from terminated_in_warehouse
                 )
  )
  update session
    set
      version = version + 1,
      termination_reason = 'canceled'
    where public_id in
            (
              select session_id
              from not_terminated_in_warehouse
            );

commit;