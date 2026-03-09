-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- Replaces function from 0/51_connection.up.sql
-- Remove call to terminate_session_if_possible
drop trigger update_connection_state_on_closed_reason on session_connection;
drop function update_connection_state_on_closed_reason();

-- Removed in 90/01_remove_session_connection_state.up.sql
create function update_connection_state_on_closed_reason() returns trigger
as $$
    begin
        if new.closed_reason is not null then
            -- check to see if there's a closed state already, before inserting a new one.
            perform from
                session_connection_state cs
            where
                    cs.connection_id = new.public_id and
                    cs.state = 'closed';
            if not found then
                insert into session_connection_state (connection_id, state)
                values
                    (new.public_id, 'closed');
            end if;
        end if;
    return new;
    end;
$$ language plpgsql;

create trigger update_connection_state_on_closed_reason after update of closed_reason on session_connection
    for each row execute procedure update_connection_state_on_closed_reason();

-- Remove function, defined in 0/51_connection.up.sql
drop function terminate_session_if_possible;

commit;
