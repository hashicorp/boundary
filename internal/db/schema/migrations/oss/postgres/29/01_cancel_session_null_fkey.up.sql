-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

drop function cancel_session(in sessionId text);

-- Updates cancel_session() from 0/50_session to check if a session is either terminated or canceling
-- Sessions can progress directly to terminated without going through the canceling state
-- cancel_session will insert a cancel state for the session, if there's isn't
-- a canceled or terminated state already.  It's used by cancel_session_with_null_fk.
-- Replaced in 92/03_cancel_session_trigger.up.sql
create function cancel_session(in sessionId text) returns void
as $$
declare
  rows_affected numeric;
begin
  insert into session_state(session_id, state)
  select
    sessionId::text, 'canceling'
  from
    session s
  where
      s.public_id = sessionId::text and
      s.public_id not in (
      select
        session_id
      from
        session_state
      where
          session_id = sessionId::text and
          state in('canceling','terminated')
    ) limit 1;
  get diagnostics rows_affected = row_count;
  if rows_affected > 1 then
    raise exception 'cancel session: more than one row affected: %', rows_affected;
  end if;
end;
$$ language plpgsql;

commit;
