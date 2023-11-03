-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- user contains the boundary user information for the boundary user that owns
-- the information in the cache.
create table if not exists user (
  -- The id of the user resource from boundary
  id text not null primary key
    check (length(id) > 0),
  -- The address of the boundary instance that this user id comes from
  address text not null
    check (length(address) > 0)
);

-- Contains the known resource types contained in the boundary client cache
create table if not exists resource_type_enm(
  string text not null primary key
    constraint only_predefined_resource_types_allowed
    check(string in ('unknown', 'target', 'session'))
);

insert into resource_type_enm (string)
values
  ('unknown'),
  ('target'),
  ('session');

-- Contains refresh tokens for list requests sent by the client daemon to the
-- boundary instance.
create table if not exists refresh_token(
  user_id text not null
    references user(id)
    on delete cascade,
  resource_type text not null
    references resource_type_enm(string)
    constraint only_known_resource_types_allowed,
  refresh_token text not null
    check (length(refresh_token) > 0),
  update_time timestamp not null default (strftime('%Y-%m-%d %H:%M:%f','now')),
  create_time timestamp not null default (strftime('%Y-%m-%d %H:%M:%f','now')),
  primary key (user_id, resource_type)
);

create trigger immutable_columns_refresh_token before update on refresh_token
for each row 
when 
  new.create_time <> old.create_time 
begin
  select raise(abort, 'immutable column');
end;


create trigger update_time_column_refresh_token before update on refresh_token
for each row 
when 
  new.refresh_token <> old.refresh_token 
begin
  update refresh_token set update_time = datetime('now','localtime') where rowid == new.rowid;
end;

-- Contains the boundary auth token
create table if not exists auth_token (
  -- id is the boundary id of the auth token
  id text not null primary key
    check (length(id) > 0),
  -- user id is the boundary user id the auth token is associated with
  user_id text not null
    references user(id)
    on delete cascade,
  -- the last time this the auth token was used on this machine to access
  -- boundary outside of the context of the cache.
  last_accessed_time timestamp not null
    default (strftime('%Y-%m-%d %H:%M:%f','now')),
  expiration_time timestamp not null
);

-- *delete_orphaned_users triggers delete a user when it no longer has any
-- auth tokens associated with them
create trigger token_update_delete_orphaned_users after update on auth_token
begin
delete from user
where
    id not in (select user_id from auth_token);
end;

create trigger token_delete_delete_orphaned_users after delete on auth_token
begin
delete from user
where
    id not in (select user_id from auth_token);
end;

create table if not exists keyring_token (
  -- the name of the keyring type on the local machine
  keyring_type text not null
    check (length(keyring_type) > 0),
  -- the name of the stored token on the keyring
  token_name text not null
    check (length(token_name) > 0),
  -- the boundary auth token id stored at in this keyring using the token name
  auth_token_id text not null
    references auth_token(id)
    on delete cascade,
  primary key (keyring_type, token_name)
);

-- target contains cached boundary target resource for a specific user and with
-- specific fields extracted to facilitate searching over those fields
create table if not exists target (
  -- the boundary user id of the user who has was able to read/list this target
  user_id text not null
    references user(id)
    on delete cascade,
  -- the boundary id of the target
  id text not null
    check (length(id) > 0),
  -- the following fields are used for searching and are set to the values
  -- from the boundary resource
  name text,
  description text,
  address text,
  -- item is the json representation of this resource from the perspective of
  -- the the requesting user.
  item text,
  primary key (user_id, id)
);

-- session contains cached boundary session resource for a specific user and
-- with specific fields extracted to facilitate searching over those fields
create table if not exists session (
  -- the boundary user id of the user who has was able to read/list this resource
  user_id text not null
    references user(id)
    on delete cascade,
  -- the resource id from boundary of this session
  id text not null
    check (length(id) > 0),
  -- the following fields are used for searching and are set to the values
  -- from the boundary resource
  endpoint text,
  type text,
  status text,
  -- item is the json representation of this resource from the perspective of
  -- of the user whose id is set in user_id
  item text,
  primary key (user_id, id)
);

-- contains errors from the last attempt to sync data from boundary for a
-- specific resource type
create table if not exists api_error (
  user_id text not null
    references user(id)
    on delete cascade,
  resource_type text not null
    references resource_type_enm(string)
    constraint only_known_resource_types_allowed,
  error text not null,
  create_time timestamp not null default current_timestamp,
  primary key (user_id, resource_type)
);

commit;
