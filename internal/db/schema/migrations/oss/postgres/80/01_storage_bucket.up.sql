-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

drop trigger immutable_columns on storage_plugin_storage_bucket;

create trigger immutable_columns before update on storage_plugin_storage_bucket
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time', 'bucket_name', 'bucket_prefix');

commit;