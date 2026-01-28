-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index auth_token_create_time_public_id_idx
      on auth_token (create_time desc, public_id desc);
  create index auth_token_update_time_public_id_idx
      on auth_token (update_time desc, public_id desc);

  analyze auth_token;

commit;
