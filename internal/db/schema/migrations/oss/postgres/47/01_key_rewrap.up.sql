-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- make the required schema changes to upgrade the dependency:
-- github.com/hashicorp/go-kms-wrapping/extras/kms/v2
-- this migration is from:
-- https://github.com/hashicorp/go-kms-wrapping/blob/main/extras/kms/migrations/postgres/05_key_rewrap.up.sql

begin;

-- we need to make the key and version columns mutable in order to support
-- rewrapping the root key versions.
drop trigger kms_immutable_columns on kms_root_key_version;

create trigger kms_immutable_columns before update on kms_root_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'create_time');


-- we need to make the key and version columns mutable in order to support
-- rewrapping the data key version.
drop trigger kms_immutable_columns on kms_data_key_version;

-- trigger updated again in migration 56 file 04
create trigger kms_immutable_columns before update on kms_data_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'data_key_id', 'root_key_version_id', 'create_time');

commit;
