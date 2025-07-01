-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- kms_version is a one row table to keep the version
create table kms_schema_version (
    version text not null,
    create_time timestamp not null default current_timestamp,
    update_time timestamp not null default current_timestamp
);

-- ensure that it's only ever one row
create unique index kms_schema_version_one_row
ON kms_schema_version((version is not null));

create trigger kms_immutable_columns_kms_schema_version
before update on kms_schema_version
for each row 
  when 
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;


create trigger update_time_column_kms_version
before update on kms_schema_version
for each row 
when 
  new.version <> old.version 
  begin
    update kms_schema_version set update_time = datetime('now','localtime') where rowid == new.rowid;
  end;


insert into kms_schema_version(version) values('v0.0.1')