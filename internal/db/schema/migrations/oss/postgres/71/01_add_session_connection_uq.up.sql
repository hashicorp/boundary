-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Adds a unique constraint so that the recording_connection
  -- table can use a foreign key matching both of these.
  alter table session_connection
    add constraint session_connection_session_id_public_id_uq
    unique (session_id, public_id);

commit;
