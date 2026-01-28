-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table kms_oplog_root_key (
  private_id kms_private_id primary key,
  scope_id kms_scope_id not null unique, -- there can only be one root key for a scope.
  -- intentionally, not creating a FK to iam_scope
  create_time kms_timestamp
);
comment on table kms_oplog_root_key is
  'kms_oplog_root_key defines a root key for an oplog scope';

-- define the immutable fields for kms_oplog_root_key (all of them)
create trigger kms_immutable_columns before update on kms_oplog_root_key
  for each row execute procedure kms_immutable_columns('private_id', 'scope_id', 'create_time');

-- not adding the kms_default_create_time_column trigger until after we've
-- converted the data (we don't want the timestamp to change)

create table kms_oplog_root_key_version (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    constraint kms_oplog_root_key_fkey
      references kms_oplog_root_key(private_id)
      on delete cascade
      on update cascade,
  version kms_version,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time kms_timestamp,
  constraint kms_oplog_root_key_version_root_key_id_version_uq
    unique(root_key_id, version)
);
comment on table kms_oplog_root_key_version is
  'kms_oplog_root_key_version contains versions of a kms_oplog_root_key';

 -- define the immutable fields for kms_root_key_version (all of them)
create trigger kms_immutable_columns before update on kms_oplog_root_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'create_time');

-- not adding the kms_default_create_time_column or kms_version_column triggers
-- until after we've converted the data (we don't want the timestamp or versions
-- to change)

create table kms_oplog_data_key (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    constraint kms_oplog_root_key_fkey
      references kms_oplog_root_key(private_id)
      on delete cascade
      on update cascade,
  purpose text not null
    constraint not_start_end_whitespace_purpose
    check (length(trim(purpose)) = length(purpose)),
  create_time kms_timestamp,
  constraint kms_oplog_data_key_root_key_id_purpose_uq
    unique (root_key_id, purpose) -- there can only be one dek for a specific purpose per root key
);
comment on table kms_oplog_data_key is
  'kms_oplog_data_key contains oplog deks (data keys)';

 -- define the immutable fields for kms_oplog_data_key (all of them)
create trigger kms_immutable_columns before update on kms_oplog_data_key
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'purpose', 'create_time');

-- not adding the kms_default_create_time_column trigger until after we've
-- converted the data (we don't want the timestamp to change)

create table kms_oplog_data_key_version (
  private_id kms_private_id primary key,
  data_key_id kms_private_id not null
    constraint kms_oplog_data_key_fkey
      references kms_oplog_data_key(private_id)
      on delete cascade
      on update cascade,
  root_key_version_id kms_private_id not null
    constraint kms_oplog_root_key_version_fkey
      references kms_oplog_root_key_version(private_id)
      on delete cascade
      on update cascade,
  version kms_version,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time kms_timestamp,
  constraint kms_oplog_data_key_version_data_key_id_version_uq
    unique(data_key_id, version)
);
comment on table kms_oplog_data_key_version is
  'kms_oplog_data_key_version contains versions of a kms_oplog_data_key (dek aka data keys)';

 -- define the immutable fields for kms_oplog_data_key_version (all of them)
create trigger kms_immutable_columns before update on kms_oplog_data_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'data_key_id', 'create_time');

-- not adding the kms_default_create_time_column or kms_version_column triggers
-- until after we've converted the data (we don't want the timestamp or versions
-- to change)

-- ############################################################################
-- Next: we will convert all the existing oplog DEK into the new schema model
-- before adding triggers for create_time, and version
-- this is important, especially for the version column!

-- convert KEK tables
insert into kms_oplog_root_key (private_id, scope_id, create_time)
select private_id, scope_id, create_time
from kms_root_key;

insert into kms_oplog_root_key_version (private_id, root_key_id, version, key, create_time)
select private_id, root_key_id, version, key, create_time
from kms_root_key_version;

-- convert oplog DEKs
insert into kms_oplog_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'oplog', create_time
from kms_data_key where purpose = 'oplog';

insert into kms_oplog_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select kdkv.private_id, kdkv.data_key_id, kdkv.root_key_version_id, kdkv.version, kdkv.key, kdkv.create_time
from kms_data_key_version kdkv, kms_oplog_data_key kodk
where kdkv.data_key_id = kodk.private_id;

-- truncate oplog_entry table, this is required because in v0.13.0 we
-- inadvertently used kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeDatabase)
-- which resulted in the use of a database key for an oplog entry.  See:
-- https://github.com/hashicorp/boundary/pull/3665/files#diff-bcf83b5283886c98fc45b6435fdc94d87d545b2768c6beac8acd14eb9d6b13f1  
truncate oplog_entry cascade;

-- ############################################################################
-- post conversion, we add the required triggers

create trigger kms_default_create_time_column before insert on kms_oplog_root_key
  for each row execute procedure kms_default_create_time();

create trigger kms_default_create_time_column before insert on kms_oplog_root_key_version
  for each row execute procedure kms_default_create_time();

create trigger kms_version_column before insert on kms_oplog_root_key_version
  for each row execute procedure kms_version_column('root_key_id');

create trigger default_create_time_column before insert on kms_oplog_data_key
  for each row execute procedure kms_default_create_time();

create trigger default_create_time before insert on kms_oplog_data_key_version
  for each row execute procedure kms_default_create_time();

create trigger kms_version_column before insert on kms_oplog_data_key_version
  for each row execute procedure kms_version_column('data_key_id');

commit;
