-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(12);

    -- Ensure session state table is populated
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

    -- Invalid duplicate state
    select throws_ok($$ insert into session_state  ( session_id, state )
        values  ('s1_____clare','pending')$$);

    -- Invalid state transition from terminated to pending
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______cindy','pending')$$);

    -- Invalid state transition from terminated to active
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______cindy','active')$$);

    -- Invalid state transition from terminated to canceling
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______cindy','canceling')$$);

    -- Invalid state transition from terminated to terminated
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______cindy','terminated')$$);

    -- Invalid state transition from active to pending
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______carly','pending')$$);

    -- Invalid state transition from canceling to pending
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______ciara','pending')$$);

    -- Invalid state transition from canceling to active
    select throws_ok($$ insert into session_state  ( session_id, state)
        values  ('s1______ciara','active')$$);

    select * from finish();
rollback;