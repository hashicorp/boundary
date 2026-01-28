-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select has_index(
    'recording_session',
    'recording_session_create_time_public_id_delete_time_delete_idx',
    array['create_time', 'public_id', 'delete_time', 'delete_after']
  );
  select has_index(
    'recording_session',
    'recording_session_update_time_public_id_delete_time_delete_idx',
    array['update_time', 'public_id', 'delete_time', 'delete_after']
  );

  select * from finish();

rollback;
