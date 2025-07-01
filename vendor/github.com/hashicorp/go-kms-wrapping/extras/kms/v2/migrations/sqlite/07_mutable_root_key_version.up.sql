-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- we need to make the root_key_version_id column mutable in order to support
-- rewrapping the data key version.
drop trigger kms_immutable_columns_kms_data_key_version;

create trigger kms_immutable_columns_kms_data_key_version
before update on kms_data_key_version
for each row 
  when 
    new.private_id <> old.private_id or 
    new.data_key_id <> old.data_key_id or
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;
  