-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the update time queries.
  create index session_create_time_public_id_idx
      on session (create_time desc, public_id asc);
  create index session_update_time_public_id_idx
      on session (update_time desc, public_id asc);

  analyze session;

commit;