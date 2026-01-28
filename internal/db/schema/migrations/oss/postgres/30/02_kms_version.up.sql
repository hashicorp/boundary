-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- make the required schema changes to adopt
-- github.com/hashicorp/go-kms-wrapping/extras/kms/v2 
-- this migration is from:
-- https://github.com/hashicorp/go-kms-wrapping/blob/main/extras/kms/migrations/postgres/02_version.up.sql 

create table kms_schema_version(
    version text not null,
    create_time kms_timestamp,
    update_time kms_timestamp
);
comment on table kms_schema_version is
  'kms_schema_version contains the kms schema version';

-- this index ensures that there will only ever be one row in the 
-- table.  see:
-- https://www.postgresql.org/docs/current/indexes-expressional.html
create unique index kms_schema_version_one_row
ON kms_schema_version((version is not null));

 -- define the immutable fields for kms_root_key (all of them)
create trigger kms_immutable_columns before update on kms_schema_version
  for each row execute procedure kms_immutable_columns('create_time');

create trigger kms_default_create_time_column before insert on kms_schema_version
  for each row execute procedure kms_default_create_time();

create trigger kms_update_time_column before update on kms_schema_version
	for each row execute procedure kms_update_time_column();

insert into kms_schema_version(version) values('v0.0.1');

commit;
