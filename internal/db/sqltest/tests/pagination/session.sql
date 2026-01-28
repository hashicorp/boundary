-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select has_index('session', 'session_project_id_create_time_list_idx', array['project_id', 'create_time', 'public_id', 'termination_reason']);
  select has_index('session', 'session_project_id_update_time_list_idx', array['project_id', 'update_time', 'public_id', 'termination_reason']);
  select has_index('session', 'session_user_id_project_id_create_time_list_idx', array['user_id', 'project_id', 'create_time', 'public_id', 'termination_reason']);
  select has_index('session', 'session_user_id_project_id_update_time_list_idx', array['user_id', 'project_id', 'update_time', 'public_id', 'termination_reason']);

  select * from finish();

rollback;
