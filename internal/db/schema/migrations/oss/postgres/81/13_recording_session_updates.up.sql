-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index recording_session_create_time_public_id_idx
      on recording_session (create_time desc, public_id desc);
  create index recording_session_update_time_public_id_idx
      on recording_session (update_time desc, public_id desc);

  analyze recording_session;

commit;
