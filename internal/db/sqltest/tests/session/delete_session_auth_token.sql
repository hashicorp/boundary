-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(12);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have a session for both auth token
  select is(count(*), 2::bigint) from session where auth_token_id = 'tok____clare';
  select is(count(*), 2::bigint) from session where auth_token_id = 'tok____carly';
  
  -- Delete auth tokens, expect no errors
  delete from auth_token where public_id = 'tok____clare' or public_id = 'tok____carly';
  select is(count(*), 0::bigint) from auth_token where public_id = 'tok____clare';
  select is(count(*), 0::bigint) from auth_token where public_id = 'tok____carly';

  -- Ensure we no longer have sessions associated with auth tokens
  select is(count(*), 0::bigint) from session where auth_token_id = 'tok____clare';
  select is(count(*), 0::bigint) from session where auth_token_id = 'tok____carly';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;
