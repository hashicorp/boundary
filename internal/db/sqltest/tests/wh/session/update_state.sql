-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(8);

  select is(count(*),                1::bigint)                from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(total_bytes_up,          null)                     from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(total_bytes_down,        null)                     from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(session_terminated_time, 'infinity'::wh_timestamp) from wh_session_accumulating_fact where session_id = 's1_____clare';

  update session_connection set
    bytes_up = 10,
    bytes_down = 5,
    closed_reason = 'closed by end-user'
  where public_id = 's1c1___clare';
  update session set
    termination_reason = 'closed by end-user'
  where public_id = 's1_____clare';

  select is(count(*),                1::bigint)                from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(total_bytes_up,          10::wh_bytes_transmitted) from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(total_bytes_down,        5::wh_bytes_transmitted)  from wh_session_accumulating_fact where session_id = 's1_____clare';
  select is(session_terminated_time, now()::wh_timestamp)      from wh_session_accumulating_fact where session_id = 's1_____clare';

  select * from finish();
rollback;
