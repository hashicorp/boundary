-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(7);

    -- Ensure session state table is populated
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';

    -- Valid state transition from pending to canceling
    insert into session_state
    ( session_id, state)
    values
        ('s1_____clare','canceling');
    select is(count(*), 2::bigint) from session_state where session_id = 's1_____clare';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='canceling';


    -- Valid state transition from active to canceling
    insert into session_state
    ( session_id, state)
    values
        ('s1_____carly','canceling');
    select is(count(*), 3::bigint) from session_state where session_id = 's1_____carly';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='canceling';

    select * from finish();

rollback;