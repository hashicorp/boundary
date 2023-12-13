-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select has_index('host_plugin_host', 'host_plugin_host_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('host_plugin_host', 'host_plugin_host_update_time_public_id_idx', array['update_time', 'public_id']);

  select has_index('static_host', 'static_host_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('static_host', 'static_host_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;
