-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- kms_audit_key entries are DEKs for crypto operations on audit entries.
create table kms_audit_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null unique -- there can be only one audit dek per root key
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_audit_key (all of them)
create trigger immutable_columns before update on kms_audit_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

-- define the value of kms_audit_key's create_time
create trigger default_create_time_column before insert on kms_audit_key
  for each row execute procedure default_create_time();

-- kms_audit_key_version entries are version of DEK keys used crypto operations on audit entries.
-- entries. 
create table kms_audit_key_version (
  private_id wt_private_id primary key,
  audit_key_id wt_private_id not null
    references kms_audit_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  constraint kms_audit_key_version_audit_key_id_uq
    unique(audit_key_id, version)
);

 -- define the immutable fields for kms_audit_key_version (all of them)
create trigger immutable_columns before update on kms_audit_key_version
  for each row execute procedure immutable_columns('private_id', 'audit_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
-- define the value of kms_audit_key_version's create_time
create trigger default_create_time_column before insert on kms_audit_key_version
  for each row execute procedure default_create_time();

-- define the value of kms_audit_key_version's version column
create trigger kms_version_column before insert on kms_audit_key_version
	for each row execute procedure kms_version_column('audit_key_id');

commit;
