-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  -- Partial index to aid session list requests
  --
  -- If a session list request is made using the default list request options
  -- and using the standard grants created by boundary by default,
  -- it will include where clauses that:
  --  * include a project_id paired with a user_id
  --  * and where termination_reason is null
  create index session_list_pix on session (project_id, user_id, termination_reason) where termination_reason is null;
  analyze session;
end;
