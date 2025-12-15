-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  delete from session
  using session_state
  where
    session.public_id = session_state.session_id
  and
    session_state.state = 'terminated'
  and
    session_state.start_time < wt_sub_seconds_from_now(3600);

  analyze;
commit;
