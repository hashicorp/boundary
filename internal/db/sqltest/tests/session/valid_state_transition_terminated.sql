-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(9);

    -- Ensure session state table is populated
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';

    -- Valid state transition from pending to terminated
    insert into session_state
    ( session_id, state)
    values
        ('s1_____clare','terminated');
    select is(count(*), 2::bigint) from session_state where session_id = 's1_____clare';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='terminated';


    -- Valid state transition from active to terminated
    insert into session_state
    ( session_id, state)
    values
        ('s1_____carly','terminated');
    select is(count(*), 3::bigint) from session_state where session_id = 's1_____carly';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='terminated';

    -- Valid state transition from canceling to terminated
    insert into session_state
    ( session_id, state)
    values
        ('s1_____ciara','terminated');
    select is(count(*), 3::bigint) from session_state where session_id = 's1_____ciara';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='terminated';

    select * from finish();
rollback;