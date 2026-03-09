-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(6);

    -- Ensure session connection table is populated
    select is(count(*), 2::bigint) from session_connection;

    -- Check that both session connections are in the authorized state (null connected_time_range)
    select is(count(*), 2::bigint) from session_connection where connected_time_range is null;

    -- Connect one of the session connections
    update session_connection
       set connected_time_range=tstzrange(now(),'infinity')
     where public_id = 's1c1___clare';
    select is(count(*), 1::bigint) from session_connection where upper(connected_time_range) > now();

    -- Close the other session connection
    update session_connection
       set closed_reason = 'unknown'
     where public_id = 's2c1___clare';
    select is(count(*), 1::bigint) from session_connection where upper(connected_time_range) <= now();

    -- Attempt to connect the closed session connection, expect an error
    select throws_ok($$ update session_connection
                           set connected_time_range = tstzrange(now(), 'infinity')
                         where public_id = 's2c1___clare'$$);

    -- Still only 1 connected session
    select is(count(*), 1::bigint) from session_connection where upper(connected_time_range) > now();

    select * from finish();
rollback;

