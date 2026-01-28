-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- the storage_plugin_storage_bucket_secret table was replaced by storage_bucket_credential_managed_secret
  -- in migration 88/01_storage_bucket_credential.up.sql.
  -- the storage_plugin_storage_bucket_secret-rewrapping-job was replaced by storage_bucket_credential_managed_secret-rewrapping-job.
  delete from job where name = 'storage_plugin_storage_bucket_secret-rewrapping-job';
commit;