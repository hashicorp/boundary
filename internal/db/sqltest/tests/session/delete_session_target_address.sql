-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(9);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1______cora' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have 2 sessions using this target address
  select is(count(*), 2::bigint) from session_target_address where target_id = 't_________cg';

  -- Delete target address, expect no errors
  delete from target_address where target_id = 't_________cg';
  select is(count(*), 0::bigint) from target_address where target_id = 't_________cg';

  -- Ensure we no longer have sessions associated with this target address
  select is(count(*), 0::bigint) from session_target_address where target_id = 't_________cg';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1______cora';

  select * from finish();
rollback;
