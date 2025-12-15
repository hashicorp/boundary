-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- this migration is from:
-- https://github.com/hashicorp/go-kms-wrapping/blob/main/extras/kms/migrations/postgres/07_mutable_root_key_version.up.sql

-- we need to make the root_key_version_id mutable in order to support
-- rewrapping the data key version.
drop trigger kms_immutable_columns on kms_data_key_version;

create trigger kms_immutable_columns before update on kms_data_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'data_key_id', 'create_time');

commit;
