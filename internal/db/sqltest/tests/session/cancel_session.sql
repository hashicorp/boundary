-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(22);

  -- Canceling a terminated session should cause no errors, but should not change state.
  prepare cancel_terminated as
    select cancel_session('s1_____cindy');
  -- to start s1_____cindy should have 2 states, and the terminated should be the active state.
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____cindy';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____cindy'
     and state = 'terminated'
     and upper(active_time_range) is null;
  -- now attempt to cancel
  select lives_ok('cancel_terminated');
  -- there should be no changes to the state
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____cindy';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____cindy'
     and state = 'terminated'
     and upper(active_time_range) is null;

  -- Canceling a canceling session should cause no errors, but should not change state.
  prepare cancel_canceling as
    select cancel_session('s1_____ciara');
  -- to start s1_____ciara should have 2 states, and the canceling should be the active state.
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____ciara';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____ciara'
     and state = 'canceling'
     and upper(active_time_range) is null;
  -- now attempt to cancel
  select lives_ok('cancel_canceling');
  -- there should be no changes to the state
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____ciara';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____ciara'
     and state = 'canceling'
     and upper(active_time_range) is null;

  -- Canceling an active session should cause no errors and should result the state changing to canceling.
  prepare cancel_active as
    select cancel_session('s1_____carly');
  -- to start s1_____carly should have 2 states, and the active should be the active state.
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____carly';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____carly'
     and state = 'active'
     and upper(active_time_range) is null;
  -- now attempt to cancel
  select lives_ok('cancel_active');
  -- there should be a new state and active should no long be the active state.
  select is(count(*), 3::bigint)
    from session_state
   where session_id = 's1_____carly';
  select is(count(*), 0::bigint)
    from session_state
   where session_id = 's1_____carly'
     and state = 'active'
     and upper(active_time_range) is null;
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____carly'
     and state = 'canceling'
     and upper(active_time_range) is null;

  -- Canceling a pending session should cause no errors and should result the state changing to canceling.
  prepare cancel_pending as
    select cancel_session('s1_____clare');
  -- to start s1_____clare should have 2 states, and the active should be the active state.
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____clare';
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____clare'
     and state = 'pending'
     and upper(active_time_range) is null;
  -- now attempt to cancel
  select lives_ok('cancel_pending');
  -- there should be a new state and pending should no long be the active state.
  select is(count(*), 2::bigint)
    from session_state
   where session_id = 's1_____clare';
  select is(count(*), 0::bigint)
    from session_state
   where session_id = 's1_____clare'
     and state = 'pending'
     and upper(active_time_range) is null;
  select is(count(*), 1::bigint)
    from session_state
   where session_id = 's1_____clare'
     and state = 'canceling'
     and upper(active_time_range) is null;

  select * from finish();
rollback;
