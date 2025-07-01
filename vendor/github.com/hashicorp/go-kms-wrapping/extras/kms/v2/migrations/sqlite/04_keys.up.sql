-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

create table kms_root_key (
    private_id text not null primary key
    check(
        length(trim(private_id) > 0)
    ),
    scope_id text not null unique
    check(
        length(trim(scope_id)) > 0
    ),
    create_time timestamp not null default current_timestamp
);

create trigger kms_immutable_columns_kms_root_key
before update on kms_root_key
for each row 
  when 
    new.private_id <> old.private_id or 
    new.scope_id <> old.scope_id or
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;

create trigger kms_default_create_time_column_kms_root_key
before insert on kms_root_key
for each row
begin
	update kms_root_key set create_time = datetime('now','localtime') where rowid = new.rowid;
end;

create table kms_root_key_version (
  private_id text not null primary key
   check(
        length(trim(private_id) > 0)
    ),
  root_key_id  text not null
    references kms_root_key(private_id) 
    on delete cascade 
    on update cascade,
  version int,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time timestamp not null default current_timestamp,
  unique(root_key_id, version)
);

create trigger kms_immutable_columns_kms_root_key_version
before update on kms_root_key_version
for each row 
  when 
    new.private_id <> old.private_id or 
    new.root_key_id <> old.root_key_id or
    new.version <> old.version or
    new.key <> old.key or
    new.version <> old.version or
    new.create_time <> old.create_time  
	begin
	  select raise(abort, 'immutable column');
	end;

create trigger kms_default_create_time_column_kms_root_key_version
before insert on kms_root_key_version
for each row
begin
	update kms_root_key_version set create_time = datetime('now','localtime') where rowid = new.rowid;
end;

create trigger version_column_kms_root_key_version
after insert on kms_root_key_version
for each row
begin
  update kms_root_key_version set version =
  (
    select max(coalesce(version,0)) + 1 
    from kms_root_key_version 
    where 
      root_key_id = new.root_key_id 
  )
  where rowid = new.rowid;  
end;

create table kms_data_key (
  private_id text not null primary key
   check(
        length(trim(private_id) > 0)
    ),
  root_key_id  text not null
    references kms_root_key(private_id) 
    on delete cascade 
    on update cascade,
  purpose text not null
    check(length(trim(purpose)) = length(purpose)),
  create_time timestamp not null default current_timestamp,
  unique (root_key_id, purpose) -- there can only be one dek per purpose per root key
);

create trigger kms_immutable_columns_kms_data_key
before update on kms_data_key
for each row 
  when 
    new.private_id <> old.private_id or 
    new.root_key_id <> old.root_key_id or
    new.purpose <> old.purpose or
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;

create trigger kms_default_create_time_column_kms_data_key
before insert on kms_data_key
for each row
begin
	update kms_data_key set create_time = datetime('now','localtime') where rowid = new.rowid;
end;

create table kms_data_key_version (
  private_id text not null primary key
   check(
        length(trim(private_id) > 0)
    ),
  data_key_id text not null
    references kms_data_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id text not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version int,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time timestamp not null default current_timestamp,
  unique(data_key_id, version)
);

create trigger kms_immutable_columns_kms_data_key_version
before update on kms_data_key_version
for each row 
  when 
    new.private_id <> old.private_id or 
    new.data_key_id <> old.data_key_id or
    new.root_key_version_id <> old.root_key_version_id or
      new.version <> old.version or
    new.key <> old.key or
    new.create_time <> old.create_time 
	begin
	  select raise(abort, 'immutable column');
	end;

create trigger kms_default_create_time_column_kms_data_key_version
before insert on kms_data_key_version
for each row
begin
	update kms_data_key_version set create_time = datetime('now','localtime') where rowid = new.rowid;
end;

create trigger version_column_kms_data_key_version
after insert on kms_data_key_version
for each row
begin
  update kms_data_key_version set version =
  (
    select max(coalesce(version,0)) + 1
    from kms_data_key_version 
    where 
      data_key_id = new.data_key_id
  )
  where rowid = new.rowid;  
end;