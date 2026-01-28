-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- make the required schema changes to adopt
-- github.com/hashicorp/go-kms-wrapping/extras/kms/v2 
-- this migration is from:
-- https://github.com/hashicorp/go-kms-wrapping/blob/main/extras/kms/migrations/postgres/04_keys.up.sql 


alter table kms_root_key rename to kms_deprecated_root_key;
alter table kms_root_key_version rename to kms_deprecated_root_key_version;

create table kms_root_key (
  private_id kms_private_id primary key,
  scope_id kms_scope_id not null unique -- there can only be one root key for a scope.
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  create_time kms_timestamp
);
comment on table kms_root_key is
  'kms_root_key defines a root key for a scope';

-- define the immutable fields for kms_root_key (all of them)
create trigger kms_immutable_columns before update on kms_root_key
  for each row execute procedure kms_immutable_columns('private_id', 'scope_id', 'create_time');

-- not adding the kms_default_create_time_column trigger until after we've
-- converted the data (we don't want the timestamp to change)

create table kms_root_key_version (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    constraint kms_root_key_fkey
      references kms_root_key(private_id) 
      on delete cascade 
      on update cascade,
  version kms_version,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time kms_timestamp,
  constraint kms_root_key_version_root_key_id_version_uq
    unique(root_key_id, version)
);
comment on table kms_root_key_version is
  'kms_root_key_version contains versions of a kms_root_key';
  
 -- define the immutable fields for kms_root_key_version (all of them)
create trigger kms_immutable_columns before update on kms_root_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'version', 'key', 'create_time');

-- not adding the kms_default_create_time_column or kms_version_column triggers
-- until after we've converted the data (we don't want the timestamp or versions
-- to change)

create table kms_data_key (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    constraint kms_root_key_fkey
      references kms_root_key(private_id)
      on delete cascade
      on update cascade,
  purpose text not null
    constraint not_start_end_whitespace_purpose
    check (length(trim(purpose)) = length(purpose)),
  create_time kms_timestamp,
  constraint kms_data_key_root_key_id_purpose_uq
    unique (root_key_id, purpose) -- there can only be one dek for a specific purpose per root key
);
comment on table kms_data_key is
  'kms_data_key contains deks (data keys) for specific purposes';

 -- define the immutable fields for kms_data_key (all of them)
create trigger kms_immutable_columns before update on kms_data_key
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'purpose', 'create_time');

-- not adding the kms_default_create_time_column trigger until after we've
-- converted the data (we don't want the timestamp to change)

create table kms_data_key_version (
  private_id kms_private_id primary key,
  data_key_id kms_private_id not null
    constraint kms_data_key_fkey
      references kms_data_key(private_id) 
      on delete cascade 
      on update cascade, 
  root_key_version_id kms_private_id not null
    constraint kms_root_key_version_fkey
      references kms_root_key_version(private_id) 
      on delete cascade 
      on update cascade,
  version kms_version,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time kms_timestamp,
  constraint kms_data_key_version_data_key_id_version_uq
    unique(data_key_id, version)
);
-- Comment fixed in 58/01_fix_comments.up.sql
comment on table kms_data_key is
  'kms_data_key_version contains versions of a kms_data_key (dek aka data keys)';

 -- define the immutable fields for kms_data_key_version (all of them)
create trigger kms_immutable_columns before update on kms_data_key_version
  for each row execute procedure immutable_columns('private_id', 'data_key_id', 'root_key_version_id', 'version', 'key', 'create_time');

-- not adding the kms_default_create_time_column or kms_version_column triggers
-- until after we've converted the data (we don't want the timestamp or versions
-- to change)

-- ############################################################################
-- Next: we will convert all the existing KEKs/DEKs into the new schema model 
-- before adding triggers for create_time, and version
-- this is important, especially for the version column!

-- convert KEK tables
insert into kms_root_key (private_id, scope_id, create_time)
select private_id, scope_id, create_time
from kms_deprecated_root_key;

insert into kms_root_key_version (private_id, root_key_id, version, key, create_time)
select private_id, root_key_id, version, key, create_time
from kms_deprecated_root_key_version;

-- convert database DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'database', create_time
from kms_database_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, database_key_id, root_key_version_id, version, key, create_time
from kms_database_key_version;

-- convert oplog DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'oplog', create_time
from kms_oplog_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, oplog_key_id, root_key_version_id, version, key, create_time
from kms_oplog_key_version;

-- convert the audit DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'audit', create_time
from kms_audit_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, audit_key_id, root_key_version_id, version, key, create_time
from kms_audit_key_version;

-- convert the oidc DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'oidc', create_time
from kms_oidc_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, oidc_key_id, root_key_version_id, version, key, create_time
from kms_oidc_key_version;

-- convert the token DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'tokens', create_time
from kms_token_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, token_key_id, root_key_version_id, version, key, create_time
from kms_token_key_version;

-- convert the session DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'sessions', create_time
from kms_session_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, session_key_id, root_key_version_id, version, key, create_time
from kms_session_key_version;

-- ############################################################################
-- post conversion, we add the required triggers
create trigger kms_default_create_time_column before insert on kms_root_key
  for each row execute procedure kms_default_create_time();

create trigger kms_default_create_time_column before insert on kms_root_key_version
  for each row execute procedure kms_default_create_time();

create trigger kms_version_column before insert on kms_root_key_version
  for each row execute procedure kms_version_column('root_key_id');

create trigger default_create_time_column before insert on kms_data_key
  for each row execute procedure kms_default_create_time();

create trigger default_create_time before insert on kms_data_key_version
  for each row execute procedure kms_default_create_time();

create trigger kms_version_column before insert on kms_data_key_version
	for each row execute procedure kms_version_column('data_key_id');

-- Next: we will convert all the existing DEKs FKs to the new model
alter table credential_vault_token drop constraint kms_database_key_version_fkey;
alter table credential_vault_token
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table credential_vault_client_certificate drop constraint kms_database_key_version_fkey;
alter table credential_vault_client_certificate
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table auth_oidc_method drop constraint kms_database_key_version_fkey;
alter table auth_oidc_method
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table host_plugin_catalog_secret drop constraint kms_database_key_version_fkey;
alter table host_plugin_catalog_secret
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table session_credential drop constraint kms_database_key_version_fkey;
alter table session_credential
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

-- rename tables so we know that they won't be used by mistake
alter table kms_database_key_version rename to kms_deprecated_database_key_version;
alter table kms_database_key rename to kms_deprecated_database_key;

alter table kms_oplog_key_version rename to kms_deprecated_oplog_key_version;
alter table kms_oplog_key rename to kms_deprecated_oplog_key;

alter table kms_audit_key_version rename to kms_deprecated_audit_key_version;
alter table kms_audit_key rename to kms_audit_database_key;

alter table kms_oidc_key_version rename to kms_deprecated_oidc_key_version;
alter table kms_oidc_key rename to kms_deprecated_oidc_key;

alter table kms_session_key_version rename to kms_deprecated_session_key_version;
alter table kms_session_key rename to kms_deprecated_session_key;

alter table kms_token_key_version rename to kms_deprecated_token_key_version;
alter table kms_token_key rename to kms_deprecated_token_key;

commit;
