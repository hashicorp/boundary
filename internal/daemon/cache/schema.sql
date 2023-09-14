-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- user contains the boundary user information for the boundary user that owns
-- the information in the cache.
create table if not exists user (
  id text not null primary key
    check (length(id) > 0),
  address text not null
    check (length(address) > 0)
);

-- token contains the token information for a user
create table if not exists token (
  keyring_type text not null
    check (length(keyring_type) > 0),
  token_name text not null
    check (length(token_name) > 0),
  auth_token_id text not null
    check (length(auth_token_id) > 0),
  user_id text not null
    references user(id)
    on delete cascade,
  last_accessed_time timestamp not null default (strftime('%Y-%m-%d %H:%M:%f','now')),
  primary key (keyring_type, token_name)
);

-- delete_orphaned_users
create trigger token_update_delete_orphaned_users after update on token
begin
delete from user
where
    id not in (select user_id from token);
end;

create trigger token_delete_delete_orphaned_users after delete on token
begin
delete from user
where
    id not in (select user_id from token);
end;

create table if not exists target (
  user_id text not null
    references user(id)
    on delete cascade,
  id text not null
    check (length(id) > 0),
  name text,
  description text,
  address text,
  item text,
  primary key (user_id, id)
);

create table if not exists session (
  user_id text not null
    references user(id)
    on delete cascade,
  id text not null
    check (length(id) > 0),
  endpoint text,
  type text,
  status text,
  item text,
  primary key (user_id, id)
);

create table if not exists api_error (
	token_name text not null,
	resource_type text not null,
	error text not null,
	create_time timestamp not null default current_timestamp,
	primary key (token_name, resource_type)
);

commit;
