-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(9);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have 5 sessions using this project
  select is(count(*), 6::bigint) from session where project_id = 'p____bcolors';

  -- Delete project, expect no errors
  delete from iam_scope_project where scope_id = 'p____bcolors';
  select is(count(*), 0::bigint) from iam_scope_project where scope_id = 'p____bcolors';

  -- Ensure we no longer have sessions associated with this project
  select is(count(*), 0::bigint) from session where project_id = 'p____bcolors';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;
