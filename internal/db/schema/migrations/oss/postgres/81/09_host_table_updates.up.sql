-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index host_plugin_host_catalog_id_create_time_public_id_idx
      on host_plugin_host (catalog_id, create_time desc, public_id desc);
  create index host_plugin_host_catalog_id_update_time_public_id_idx
      on host_plugin_host (catalog_id, update_time desc, public_id desc);

  analyze host_plugin_host;

  -- Add new indexes for the create time and update time queries.
  create index static_host_catalog_id_create_time_public_id_idx
      on static_host (catalog_id, create_time desc, public_id desc);
  create index static_host_catalog_id_update_time_public_id_idx
      on static_host (catalog_id, update_time desc, public_id desc);

  analyze static_host;

commit;
