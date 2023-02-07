-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(9);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have 4 sessions using this host set
  select is(count(*), 4::bigint) from session_host_set_host where host_set_id = 's___1cb-sths';
  
  -- Delete host set, expect no errors
  delete from host_set where public_id = 's___1cb-sths';
  select is(count(*), 0::bigint) from host_set where public_id = 's___1cb-sths';

  -- Ensure we no longer have sessions associated with this host set
  select is(count(*), 0::bigint) from session_host_set_host where host_set_id = 's___1cb-sths';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;