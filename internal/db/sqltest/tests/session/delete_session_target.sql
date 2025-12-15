-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(12);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  select is(count(*), 3::bigint) from session where target_id = 't_________cb';
  select is(count(*), 3::bigint) from session where target_id = 'tssh______cb';

  -- Delete target, expect no errors
  delete from target where public_id='t_________cb';
  select is(count(*), 0::bigint) from target where public_id='t_________cb';

  delete from target where public_id='tssh______cb';
  select is(count(*), 0::bigint) from target where public_id='tssh______cb';

  -- Ensure we no longer have sessions associated with this target
  select is(count(*), 0::bigint) from session where target_id = 't_________cb';
  select is(count(*), 0::bigint) from session where target_id = 'tssh______cb';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;
