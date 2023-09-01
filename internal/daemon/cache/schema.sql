begin;
create table if not exists cache_persona (
  keyring_type text not null,
  token_name text not null,
  boundary_addr text not null,
  auth_token_id text not null,
  user_id text not null,
  last_accessed_time timestamp not null default (strftime('%Y-%m-%d %H:%M:%f','now')),
  unique(keyring_type, token_name, boundary_addr, user_id),
  primary key (keyring_type, token_name)
);

create table if not exists cache_target (
  keyring_type text not null,
  token_name text not null,
  boundary_addr text not null,
  boundary_user_id text not null,
  id text not null,
  name text,
  description text,
  address text,
  item text,
  foreign key (keyring_type, token_name, boundary_addr, boundary_user_id)
	references cache_persona(keyring_type, token_name, boundary_addr, user_id)
	on delete cascade,
  primary key (keyring_type, token_name, boundary_addr, boundary_user_id, id)
);

-- delete_orphaned_targets will delete targets when a persona changes to no
-- longer have the same boundary address or boundary user id
create trigger delete_orphaned_targets before update on cache_persona
begin
delete from cache_target
where
    (new.boundary_addr <> old.boundary_addr or new.user_id <> old.user_id)
  and
    keyring_type = old.keyring_type
  and
    token_name = old.token_name
  and
    boundary_addr = old.boundary_addr
  and
    boundary_user_id = old.user_id;
end;

create table if not exists cache_api_error (
	token_name text not null,
	resource_type text not null,
	error text not null,
	create_time timestamp not null default current_timestamp,
	primary key (token_name, resource_type)
);

commit;
