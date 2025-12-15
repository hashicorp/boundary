-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(3);

    -- Ensure session state table is populated
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';

    -- Valid state transition from pending to active
    insert into session_state
    ( session_id, state)
    values
        ('s1_____clare','active');

    select is(count(*), 2::bigint) from session_state where session_id = 's1_____clare';
    select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='active';

    select * from finish();
rollback;