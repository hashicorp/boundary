begin;

create table kms_external_type_enm (
  string text not null primary key check(string in ('unknown', 'devkms', 'awskms', 'gcpkms','alicloudkms', 'azurekms', 'ocikms', 'vaulttransitkms', 'hsmpkcs11kms'))
);

 -- define the immutable fields of kms_external_type_enm
create trigger 
  immutable_columns
before
update on kms_external_type_enm
  for each row execute procedure immutable_columns('string');

insert into kms_external_type_enm (string)
values
  ('unknown'),
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
  scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
  type text not null references kms_external_type_enm(string),
  config jsonb,
  create_time wt_timestamp,
  update_time wt_timestamp
);

 -- define the immutable fields for kms_external_config (only config and
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
before
update on kms_external_config
  for each row execute procedure update_time_column();

create table kms_root (
  private_id wt_private_id primary key
    references iam_scope(public_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_root (all of them)
create trigger 
  immutable_columns
before
update on kms_root
  for each row execute procedure immutable_columns('private_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_root
  for each row execute procedure default_create_time();

create table kms_root_key (
  private_id wt_private_id primary key,
  root_id  wt_private_id not null
    references kms_root(private_id)
    on delete cascade
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(root_id, version)
);

 -- define the immutable fields for kms_root_key (all of them)
create trigger 
  immutable_columns
before
update on kms_root_key
  for each row execute procedure immutable_columns('private_id', 'root_id', 'version', 'key', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_root_key
  for each row execute procedure default_create_time();

create table kms_database (
  private_id wt_private_id primary key
    references kms_root(private_id)
    on delete cascade
    on update cascade,
  foreign key (private_id)
    references iam_scope(public_id)
    on delete cascade
    on update cascade,
  create_time wt_timestamp
);

 -- define the immutable fields for kms_database (all of them)
create trigger 
  immutable_columns
before
update on kms_database
  for each row execute procedure immutable_columns('private_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on kms_database
  for each row execute procedure default_create_time();

create table kms_database_key (
  private_id wt_private_id primary key,
  database_id wt_private_id
    references kms_database(private_id)
    on delete cascade
    on update cascade,
  root_key_id wt_private_id
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  version wt_version not null default 1,
  key bytea not null,
  create_time wt_timestamp,
  unique(database_id, version)
);


 -- define the immutable fields for kms_database_key (all of them)
create trigger 
  immutable_columns
before
update on kms_database_key
  for each row execute procedure immutable_columns('private_id', 'database_id', 'root_key_id', 'version', 'key', 'create_time');
  
create trigger 
  default_create_time_column
before
insert on kms_database_key
  for each row execute procedure default_create_time();

commit;
