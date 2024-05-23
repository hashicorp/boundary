-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- update_worker_auth_authorized is a before update trigger function for the
-- worker_auth_authorized table. The worker_auth_authorized table is a child
-- table of server_worker. A row contains a set encryption keys for a
-- server_worker that are unique to that worker. A server_worker can only have
-- two rows in the worker_auth_authorized table: one with a state of 'current'
-- and one with the state of 'previous'.
--
--- This trigger function ensures that there is only ever one entry for
--  with a state of 'current' and one with a state of 'previous'.
create function update_worker_auth_authorized() returns trigger
as $$
begin
    if new.state = 'current' then
        perform
        from worker_auth_authorized
          where state = 'current';
        if found then
          raise 'current worker auth already exists; cannot set %s to current', new.worker_key_identifier;
        end if;
    end if;
    if new.state = 'previous' then
        perform
        from worker_auth_authorized
          where state = 'previous';
        if found then
          raise 'previous worker auth already exists; cannot set %s to previous', new.worker_key_identifier;
        end if;
    end if;
    return new;
end;
$$ language plpgsql;
comment on function update_worker_auth_authorized is
  'update_worker_auth_authorized is a before update trigger function for the worker_auth_authorized table.';

create trigger update_worker_auth_authorized before update on worker_auth_authorized
    for each row execute function update_worker_auth_authorized();

commit;