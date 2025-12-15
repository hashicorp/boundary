-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select has_index('host_plugin_set', 'host_plugin_set_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('host_plugin_set', 'host_plugin_set_update_time_public_id_idx', array['update_time', 'public_id']);

  select has_index('static_host_set', 'static_host_set_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('static_host_set', 'static_host_set_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;
