begin;

create table target (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null 
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  create_time wt_timestamp
);

create trigger 
  immutable_columns
before
update on target
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger 
  default_create_time_column
before
insert on target
  for each row execute procedure default_create_time();

create trigger 
  target_scope_valid
before insert on target
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

create trigger 
  immutable_columns
before
update on target_host_set
  for each row execute procedure immutable_columns('target_id', 'host_set_id', 'create_time');

create trigger 
  target_host_set_scope_valid
before
insert on target_host_set
  for each row execute procedure target_host_set_scope_valid();

create table target_tcp (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null 
    references iam_scope(public_id) 
    on delete cascade 
    on update cascade,
  name text not null, -- name is not optional for a target subtype
  description text,
  default_port int, -- default_port can be null
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  unique(scope_id, name) -- name must be unique within a scope
);


 -- define the immutable fields for target 
create trigger 
  immutable_columns
before
update on target_tcp
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger
  update_version_column
after update on target_tcp
  for each row execute procedure update_version_column();

create trigger
  update_time_column
before update on target_tcp
  for each row execute procedure update_time_column();

create trigger 
  default_create_time_column
before
insert on target_tcp
  for each row execute procedure default_create_time();

create trigger 
  target_scope_valid
before insert on target_tcp
  for each row execute procedure target_scope_valid();


-- target_all_subtypes is a union of all target subtypes 
create view target_all_subtypes
as 
select public_id, scope_id from target_tcp;

commit;
