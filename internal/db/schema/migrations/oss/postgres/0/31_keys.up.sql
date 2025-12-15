-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*
             ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐            
             ├────────────────────────────────────────────────────────────────────────────────────────────┐                           ○            
             ├────────────────────────────────────────────────────────────────┐                           ○                           ┼            
             ├────────────────────────────────────┐                           ○                           ┼              ┌────────────────────────┐
             │                                    ○                           ┼              ┌────────────────────────┐  │     kms_token_key      │
             ┼                                    ┼              ┌────────────────────────┐  │    kms_session_key     │  ├────────────────────────┤
┌────────────────────────┐           ┌────────────────────────┐  │     kms_oplog_key      │  ├────────────────────────┤  │private_id              │
│      kms_root_key      │           │    kms_database_key    │  ├────────────────────────┤  │private_id              │  │root_key_id             │
├────────────────────────┤           ├────────────────────────┤  │private_id              │  │root_key_id             │  │                        │
│private_id              │           │private_id              │  │root_key_id             │  │                        │  │                        │
│scope_id                │           │root_key_id             │  │                        │  │                        │  │                        │
│                        │           │                        │  │                        │  │                        │  └────────────────────────┘
└────────────────────────┘           └────────────────────────┘  └────────────────────────┘  └────────────────────────┘               ┼            
             ┼                                    ┼                           ┼                           ┼                           │            
             │                                    │                           │                           │                           │            
             │                                    │                           │                           │                           │            
             │                                    │                           │                           │                           │            
             │                                    │                           │                           │                           │            
             ┼                                    ┼                           ┼                           ┼                           │            
            ╱│╲                                  ╱│╲                         ╱│╲                         ╱│╲                          ┼            
┌────────────────────────┐           ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────┐              ╱│╲           
│  kms_root_key_version  │           │kms_database_key_version│  │ kms_oplog_key_version  │  │kms_session_key_version │  ┌────────────────────────┐
├────────────────────────┤           ├────────────────────────┤  ├────────────────────────┤  ├────────────────────────┤  │ kms_token_key_version  │
│private_id              │           │private_id              │  │private_id              │  │private_id              │  ├────────────────────────┤
│root_key_id             │           │database_key_id         │  │oplog_key_id            │  │session_key_id          │  │private_id              │
│key                     │           │root_key_id             │  │root_key_id             │  │root_key_id             │  │token_key_id            │
│version                 │           │key                     │  │key                     │  │key                     │  │root_key_id             │
│                        │           │version                 │  │version                 │  │version                 │  │key                     │
└────────────────────────┘           └────────────────────────┘  │                        │  │                        │  │version                 │
             ┼                                    ┼              └────────────────────────┘  │                        │  │                        │
             │                                    ○                           ┼              └────────────────────────┘  │                        │
             ├────────────────────────────────────┘                           ○                           ┼              └────────────────────────┘
             ├────────────────────────────────────────────────────────────────┘                           ○                           ┼            
             ├────────────────────────────────────────────────────────────────────────────────────────────┘                           ○            
             └────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

create table kms_root_key (
  private_id wt_private_id primary key,
  scope_id wt_scope_id not null unique -- there can only be one root key for a scope.
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_root_key (all of them)
create trigger immutable_columns before update on kms_root_key
  for each row execute procedure immutable_columns('private_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on kms_root_key
  for each row execute procedure default_create_time();

create table kms_root_key_version (
  private_id wt_private_id primary key,
  root_key_id  wt_private_id not null
    references kms_root_key(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  unique(root_key_id, version)
);

 -- define the immutable fields for kms_root_key_version (all of them)
create trigger immutable_columns before update on kms_root_key_version
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'version', 'key', 'create_time');

create trigger default_create_time_column before insert on kms_root_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column before insert on kms_root_key_version
	for each row execute procedure kms_version_column('root_key_id');

create table kms_database_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null unique -- there can be only one database dek per root key
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_database_key (all of them)
create trigger immutable_columns before update on kms_database_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger default_create_time_column before insert on kms_database_key
  for each row execute procedure default_create_time();

create table kms_database_key_version (
  private_id wt_private_id primary key,
  database_key_id wt_private_id not null
    references kms_database_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  unique(database_key_id, version)
);

 -- define the immutable fields for kms_database_key_version (all of them)
create trigger immutable_columns before update on kms_database_key_version
  for each row execute procedure immutable_columns('private_id', 'database_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger default_create_time_column before insert on kms_database_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column before insert on kms_database_key_version
	for each row execute procedure kms_version_column('database_key_id');

create table kms_oplog_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null unique -- there can be only one oplog dek per root key
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_oplog_key (all of them)
create trigger immutable_columns before update on kms_oplog_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger default_create_time_column before insert on kms_oplog_key
  for each row execute procedure default_create_time();

create table kms_oplog_key_version (
  private_id wt_private_id primary key,
  oplog_key_id wt_private_id not null
    references kms_oplog_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  unique(oplog_key_id, version)
);

 -- define the immutable fields for kms_oplog_key_version (all of them)
create trigger immutable_columns before update on kms_oplog_key_version
  for each row execute procedure immutable_columns('private_id', 'oplog_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger default_create_time_column before insert on kms_oplog_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column before insert on kms_oplog_key_version
	for each row execute procedure kms_version_column('oplog_key_id');

create table kms_session_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null unique -- there can be only one session dek per root key
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_oplog_key (all of them)
create trigger immutable_columns before update on kms_session_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger default_create_time_column before insert on kms_session_key
  for each row execute procedure default_create_time();

create table kms_session_key_version (
  private_id wt_private_id primary key,
  session_key_id wt_private_id not null
    references kms_session_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  unique(session_key_id, version)
);


 -- define the immutable fields for kms_session_key_version (all of them)
create trigger immutable_columns before update on kms_session_key_version
  for each row execute procedure immutable_columns('private_id', 'session_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger default_create_time_column before insert on kms_session_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column before insert on kms_session_key_version
	for each row execute procedure kms_version_column('session_key_id');

create table kms_token_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null unique -- there can be only one token dek per root key
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_token_key (all of them)
create trigger immutable_columns before update on kms_token_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger default_create_time_column before insert on kms_token_key
  for each row execute procedure default_create_time();

create table kms_token_key_version (
  private_id wt_private_id primary key,
  token_key_id wt_private_id not null
    references kms_token_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null,
  create_time wt_timestamp,
  unique(token_key_id, version)
);

 -- define the immutable fields for kms_token_key_version (all of them)
create trigger immutable_columns before update on kms_token_key_version
  for each row execute procedure immutable_columns('private_id', 'token_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger default_create_time_column before insert on kms_token_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column before insert on kms_token_key_version
	for each row execute procedure kms_version_column('token_key_id');

  insert into oplog_ticket
    (name, version)
  values
    ('kms_root_key', 1),
    ('kms_root_key_version', 1);
    
commit;
