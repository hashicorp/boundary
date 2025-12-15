-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select has_index('host_plugin_host', 'host_plugin_host_catalog_id_create_time_public_id_idx', array['catalog_id', 'create_time', 'public_id']);
  select has_index('host_plugin_host', 'host_plugin_host_catalog_id_update_time_public_id_idx', array['catalog_id', 'update_time', 'public_id']);

  select has_index('static_host', 'static_host_catalog_id_create_time_public_id_idx', array['catalog_id', 'create_time', 'public_id']);
  select has_index('static_host', 'static_host_catalog_id_update_time_public_id_idx', array['catalog_id', 'update_time', 'public_id']);

  select * from finish();

rollback;
