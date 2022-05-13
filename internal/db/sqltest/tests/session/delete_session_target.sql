begin;
  select plan(9);

  -- Ensure session state table is populated
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare' and state='pending';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____cindy' and state='terminated';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____ciara' and state='canceling';
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____carly' and state='active';

  -- Check that we have 4 sessions using this target
  select is(count(*), 4::bigint) from session where target_id = 't_________cb';
  
  -- Delete target, expect no errors
  delete from target where public_id='t_________cb';
  select is(count(*), 0::bigint) from target where public_id='t_________cb';

  -- Ensure we no longer have sessions associated with this target
  select is(count(*), 0::bigint) from session where target_id = 't_________cb';

  -- Ensure sessions that were pending or active are now in canceling state
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____clare';
  select is(count(*), 1::bigint) from session_state where state = 'canceling' and session_id = 's1_____carly';

  select * from finish();
rollback;