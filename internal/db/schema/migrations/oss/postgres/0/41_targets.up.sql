-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*
                                   ┌─────────────────┐
┌─────────────────┐                │   target_tcp    │
│     target      │                ├─────────────────┤
├─────────────────┤                │public_id        │
│public_id        │┼─────────────○┼│scope_id         │
│scope_id         │                │default_port     │
│                 │                │name (not null)  │
└─────────────────┘                │description      │
         ┼                         └─────────────────┘
         │                                            
         ○                                            
        ╱│╲                                           
┌─────────────────┐                                   
│ target_host_set │                                   
├─────────────────┤                                   
│target_id        │                                   
│host_set_id      │                                   
│                 │                                   
└─────────────────┘                                   
        ╲│╱                                           
         ○                                            
         │                                            
         │                                            
         ┼                                            
┌─────────────────┐                                   
│    host_set     │                                   
├─────────────────┤                                   
│public_id        │                                   
│catalog_id       │                                   
│                 │                                   
└─────────────────┘                                                                            

*/

create table target (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null 
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  create_time wt_timestamp
);

create trigger immutable_columns before update on target
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on target
  for each row execute procedure default_create_time();

create trigger target_scope_valid before insert on target
  for each row execute procedure target_scope_valid();


create table target_host_set(
  target_id wt_public_id
    references target(public_id)
    on delete cascade
    on update cascade,
  host_set_id wt_public_id
    references host_set(public_id)
    on delete cascade
    on update cascade,
  primary key(target_id, host_set_id),
  create_time wt_timestamp
);

create trigger immutable_columns before update on target_host_set
  for each row execute procedure immutable_columns('target_id', 'host_set_id', 'create_time');

create trigger target_host_set_scope_valid before insert on target_host_set
  for each row execute procedure target_host_set_scope_valid();

create table target_tcp (
  public_id wt_public_id primary key
    references target(public_id)
    on delete cascade
    on update cascade,
  scope_id wt_scope_id not null 
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  name text not null, -- name is not optional for a target subtype
  description text,
  default_port int, -- default_port can be null
   -- max duration of the session in seconds.
   -- default is 8 hours
  session_max_seconds int not null default 28800
    constraint session_max_seconds_must_be_greater_than_0
    check(session_max_seconds > 0),
  -- limit on number of session connections allowed. -1 equals no limit
  -- The default was updated in 37/01_set_unlimited_connections_limit.up.sql.
  session_connection_limit int not null default 1
    constraint session_connection_limit_must_be_greater_than_0_or_negative_1
    check(session_connection_limit > 0 or session_connection_limit = -1),
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  unique(scope_id, name) -- name must be unique within a scope
);

create trigger insert_target_subtype before insert on target_tcp
  for each row execute procedure insert_target_subtype();

create trigger delete_target_subtype after delete on target_tcp
  for each row execute procedure delete_target_subtype();

 -- define the immutable fields for target 
create trigger immutable_columns before update on target_tcp
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger update_version_column after update on target_tcp
  for each row execute procedure update_version_column();

create trigger update_time_column before update on target_tcp
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on target_tcp
  for each row execute procedure default_create_time();

create trigger target_scope_valid before insert on target_tcp
  for each row execute procedure target_scope_valid();


-- target_all_subtypes is a union of all target subtypes 
-- NOTE: this is replaced in 100 to add worker_filter
create view target_all_subtypes
as 
select 
  public_id, 
  scope_id, 
  name, 
  description, 
  default_port, 
  session_max_seconds,
  session_connection_limit,
  version, 
  create_time,
  update_time,
  'tcp' as type
  from target_tcp;

create view target_set
as
select 
  hs.public_id,
  hs.catalog_id,
  ths.target_id
from
  target_host_set ths,
  host_set hs
where
  hs.public_id = ths.host_set_id;

insert into oplog_ticket
  (name, version)
values
  ('target_tcp', 1);

commit;
