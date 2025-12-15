-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index storage_plugin_storage_bucket_create_time_public_id_idx
      on storage_plugin_storage_bucket (create_time desc, public_id desc);
  create index storage_plugin_storage_bucket_update_time_public_id_idx
      on storage_plugin_storage_bucket (update_time desc, public_id desc);

  analyze storage_plugin_storage_bucket;

commit;
