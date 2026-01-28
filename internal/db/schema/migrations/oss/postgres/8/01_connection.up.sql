-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table session_connection
  add column server_id text;

-- Note: here, and in the session table, we should add a trigger ensuring that
-- if server_id goes to null, we mark connections as closed. See
-- https://hashicorp.atlassian.net/browse/ICU-1495
alter table session_connection
  add constraint server_fkey
    foreign key (server_id)
    references server (private_id)
    on delete set null
    on update cascade;

-- We now populate the connection information from existing session information
update session_connection sc
set
  server_id = s.server_id
from
  session s
where
  sc.session_id = s.public_id;

commit;
