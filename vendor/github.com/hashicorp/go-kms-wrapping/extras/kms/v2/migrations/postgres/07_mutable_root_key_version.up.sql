-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

-- we need to make the root_key_version_id mutable in order to support
-- rewrapping the data key version.
drop trigger kms_immutable_columns on kms_data_key_version;

create trigger kms_immutable_columns
before
update on kms_data_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'data_key_id', 'create_time');

commit;
