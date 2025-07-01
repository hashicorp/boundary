-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

create table kms_collection_version (
    version kms_version,
    create_time timestamp not null default current_timestamp,
    update_time timestamp not null default current_timestamp
);

-- ensure that it's only ever one row
create unique index kms_collection_version_one_row
ON kms_collection_version((version is not null));

create trigger kms_immutable_columns
before
update on kms_collection_version
  for each row execute procedure kms_immutable_columns('create_time');

create trigger kms_update_time_column 
before 
update on kms_collection_version 
	for each row execute procedure kms_update_time_column();


insert into kms_collection_version(version) values(1);

update kms_schema_version set version = 'v0.0.2';

commit;