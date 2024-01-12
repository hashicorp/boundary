-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select has_index('recording_session', 'recording_session_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('recording_session', 'recording_session_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;
