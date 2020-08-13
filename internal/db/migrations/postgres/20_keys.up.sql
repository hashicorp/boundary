begin;

create table kms_external_type_enm (
  name text primary key check(name in (
    'unknownkms', 
    'devkms', 
    'awskms', 
    'gcpkms',
    'alicloudkms', 
    'azurekms', 
    'ocikms', 
    'vaulttransitkms', 
    'hsmpkcs11kms'))
);

 -- define the immutable fields of kms_external_type_enm
create trigger 
  immutable_columns
before
update on kms_external_type_enm
  for each row execute procedure immutable_columns('name');

insert into kms_external_type_enm (name)
values
  ('unknownkms'),
  ('devkms'),
  ('awskms'),
  ('gcpkms'),
  ('alicloudkms'),
  ('azurekms'),
  ('ocikms'),
  ('vaulttransitkms'),
  ('hsmpkcs11kms');

create table kms_external_config (
  private_id wt_private_id primary key,
  scope_id wt_scope_id not null 
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  type text not null 
    references kms_external_type_enm(name),
  config jsonb not null,
  version wt_version not null default 1,
  create_time wt_timestamp,
  update_time wt_timestamp
);

 -- define the immutable fields for kms_external_config (only version, config and
 -- update_time are updatable)
create trigger 
  immutable_columns
before
update on kms_external_config
  for each row execute procedure immutable_columns('private_id', 'scope_id', 'type', 'create_time');
  
create trigger 
  default_create_time_column
before
insert on kms_external_config
  for each row execute procedure default_create_time();

create trigger 
  update_time_column 
before update on kms_external_config 
  for each row execute procedure update_time_column();

create trigger
  update_version_column
after update on kms_external_config
  for each row execute procedure update_version_column('private_id');

create or replace function
  kms_scope_valid()
  returns trigger
as $$
declare scope_type text;
begin
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into scope_type;
  -- Always allowed
  if scope_type = 'global' then
    return new;
  end if;
  if scope_type = 'org' then
    return new;
  end if;
  raise exception 'invalid to scope type for kms external config';
end;
$$ language plpgsql;

create trigger 
  kms_scope_valid
before insert on kms_external_config
  for each row execute procedure kms_scope_valid();


create table kms_root_key (
  private_id wt_private_id primary key,
  scope_id wt_scope_id not null unique -- there can only be one root key for a scope.
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_root_key (all of them)
create trigger 
  immutable_columns
before
update on kms_root_key
  for each row execute procedure immutable_columns('private_id', 'scope_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_root_key
  for each row execute procedure default_create_time();

create trigger 
  kms_scope_valid
before insert on kms_root_key
  for each row execute procedure kms_scope_valid();

create table kms_root_key_version (
  private_id wt_private_id primary key,
  root_key_id  wt_private_id not null 
    references kms_root_key(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(root_key_id, version)
);

 -- define the immutable fields for kms_root_key_version (all of them)
create trigger 
  immutable_columns
before
update on kms_root_key_version
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'version', 'key', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_root_key_version
  for each row execute procedure default_create_time();

create table kms_database_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_database_key (all of them)
create trigger 
  immutable_columns
before
update on kms_database_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_database_key
  for each row execute procedure default_create_time();

create table kms_database_key_version (
  private_id wt_private_id primary key,
  database_id wt_private_id 
    references kms_database_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id 
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(database_id, version)
);

 -- define the immutable fields for kms_database_key_version (all of them)
create trigger 
  immutable_columns
before
update on kms_database_key_version
  for each row execute procedure immutable_columns('private_id', 'database_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger 
  default_create_time_column
before
insert on kms_database_key_version
  for each row execute procedure default_create_time();


create table kms_oplog_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_oplog_key (all of them)
create trigger 
  immutable_columns
before
update on kms_oplog_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_oplog_key
  for each row execute procedure default_create_time();

create table kms_oplog_key_version (
  private_id wt_private_id primary key,
  oplog_key_id wt_private_id 
    references kms_oplog_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id 
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(oplog_key_id, version)
);

 -- define the immutable fields for kms_oplog_key_version (all of them)
create trigger 
  immutable_columns
before
update on kms_oplog_key_version
  for each row execute procedure immutable_columns('private_id', 'oplog_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger 
  default_create_time_column
before
insert on kms_oplog_key_version
  for each row execute procedure default_create_time();

create table kms_session_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_oplog_key (all of them)
create trigger 
  immutable_columns
before
update on kms_session_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_session_key
  for each row execute procedure default_create_time();

create table kms_session_key_version (
  private_id wt_private_id primary key,
  session_key_id wt_private_id 
    references kms_session_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id 
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(session_key_id, version)
);


 -- define the immutable fields for kms_session_key_version (all of them)
create trigger 
  immutable_columns
before
update on kms_session_key_version
  for each row execute procedure immutable_columns('private_id', 'session_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger 
  default_create_time_column
before
insert on kms_session_key_version
  for each row execute procedure default_create_time();

  insert into oplog_ticket
    (name, version)
  values
    ('kms_external_config', 1);
commit;