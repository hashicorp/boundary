-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(12);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have a session for both users
  select is(count(*), 2::bigint) from session where user_id = 'u______clare';
  select is(count(*), 2::bigint) from session where user_id = 'u______carly';

  -- Delete users, expect no errors
  delete from iam_user where public_id = 'u______clare' or public_id = 'u______carly';
  select is(count(*), 0::bigint) from iam_user where public_id = 'u______clare';
  select is(count(*), 0::bigint) from iam_user where public_id = 'u______carly';

  -- Ensure we no longer have sessions associated with the users
  select is(count(*), 0::bigint) from session where user_id = 'u______clare';
  select is(count(*), 0::bigint) from session where user_id = 'u______carly';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;
