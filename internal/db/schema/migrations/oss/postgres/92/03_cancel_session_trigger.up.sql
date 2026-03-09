-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Replaces function from 29/01_cancel_session_null_fkey.up.sql
  drop function cancel_session;
  create function cancel_session(sessionid text) returns void
  as $$
  declare
    rows_affected numeric;
  begin
    insert into session_state(session_id, state)
         values              (sessionId,  'canceling');
  exception when unique_violation
              or foreign_key_violation
              or check_violation
            then
    -- Do nothing. Any one of these violations would indicate that the session
    -- either already is canceled, or is in a terminated state and cannot
    -- be canceled.
  end;
  $$ language plpgsql;
commit;
