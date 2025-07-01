-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

create table kms_collection_version (
    version int not null,
    create_time timestamp not null default current_timestamp,
    update_time timestamp not null default current_timestamp
);

-- ensure that it's only ever one row
create unique index kms_collection_version_one_row
ON kms_collection_version((version is not null));

create trigger kms_immutable_columns_kms_collection_version
before update on kms_collection_version
for each row 
  when 
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;


create trigger update_time_column_kms_collection_version
before update on kms_collection_version
for each row 
when 
  new.version <> old.version 
  begin
    update kms_collection_version set update_time = datetime('now','localtime') where rowid == new.rowid;
  end;


insert into kms_collection_version(version) values(1);

update kms_schema_version set version = 'v0.0.2';


