-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1
begin;

create table kms_oplog_collection_version (
  version kms_version,
  create_time kms_timestamp not null default current_timestamp,
  update_time kms_timestamp not null default current_timestamp
);
comment on table kms_oplog_collection_version is
  'kms_oplog_collection_version is a single-row table which stores the current version of the kms collection';

-- ensure that it's only ever one row
create unique index kms_oplog_collection_version_one_row
  on kms_oplog_collection_version((version is not null));

create trigger kms_immutable_columns before update on kms_oplog_collection_version
  for each row execute procedure kms_immutable_columns('create_time');

create trigger kms_update_time_column before update on kms_oplog_collection_version
  for each row execute procedure kms_update_time_column();


insert into kms_oplog_collection_version(version) values(1);

update kms_oplog_schema_version set version = 'v0.0.2';

commit;
