-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Partial index to aid session list requests
  --
  -- If a session list request is made using the default list request options
  -- and using the standard grants created by boundary by default,
  -- it will include where clauses that:
  --  * include a project_id paired with a user_id
  --  * and where termination_reason is null
  -- Dropped in 81/05_session_base_table_updates.up.sql.
  create index session_list_pix on session (project_id, user_id, termination_reason) where termination_reason is null;
  analyze session;
end;
