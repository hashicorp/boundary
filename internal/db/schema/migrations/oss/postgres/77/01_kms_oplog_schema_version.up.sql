
-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table kms_oplog_schema_version(
  version text not null,
  create_time kms_timestamp,
  update_time kms_timestamp
);
comment on table kms_oplog_schema_version is
  'kms_oplog_schema_version contains the kms schema version for oplog keys';

create unique index kms_oplog_schema_version_one_row
  on kms_oplog_schema_version((version is not null));

 -- define the immutable fields for kms_root_key (all of them)
create trigger kms_immutable_columns before update on kms_oplog_schema_version
  for each row execute procedure kms_immutable_columns('create_time');

create trigger kms_default_create_time_column before insert on kms_oplog_schema_version
  for each row execute procedure kms_default_create_time();

create trigger kms_update_time_column before update on kms_oplog_schema_version
  for each row execute procedure kms_update_time_column();

insert into kms_oplog_schema_version(version) values('v0.0.1');

commit;
