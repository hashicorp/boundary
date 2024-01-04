-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index host_plugin_set_create_time_public_id_idx
      on host_plugin_set (create_time desc, public_id asc);
  create index host_plugin_set_update_time_public_id_idx
      on host_plugin_set (update_time desc, public_id asc);

  analyze host_plugin_set;

  -- Add new indexes for the create time and update time queries.
  create index static_host_set_create_time_public_id_idx
      on static_host_set (create_time desc, public_id asc);
  create index static_host_set_update_time_public_id_idx
      on static_host_set (update_time desc, public_id asc);

  analyze static_host_set;

commit;
