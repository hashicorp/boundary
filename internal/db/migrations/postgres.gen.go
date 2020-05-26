// Code generated by "make migrations"; DO NOT EDIT.
package migrations

var postgresMigrations = map[string]*fakeFile{
	"migrations": {
		name: "migrations",
	},
	"migrations/01_domain_types.down.sql": {
		name: "01_domain_types.down.sql",
		bytes: []byte(`
begin;

drop domain wt_timestamp;
drop domain wt_public_id;
drop function update_time_column() cascade;
drop function immutable_create_time_func() cascade;
commit;

`),
	},
	"migrations/01_domain_types.up.sql": {
		name: "01_domain_types.up.sql",
		bytes: []byte(`
begin;

create domain wt_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_timestamp as
  timestamp with time zone
  default current_timestamp;
comment on domain wt_timestamp is
'Standard timestamp for all create_time and update_time columns';


create or replace function
  update_time_column()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    new.update_time = now();
    return new;
  else
    return old;
  end if;
end;
$$ language plpgsql;

comment on function
  update_time_column()
is
  'function used in before update triggers to properly set update_time columns';

create or replace function
  immutable_create_time_func()
  returns trigger
as $$
begin
  if new.create_time is distinct from old.create_time then
    new.create_time = old.create_time;
    raise warning 'create_time cannot be set to %', new.create_time;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  immutable_create_time_func()
is
  'function used in before update triggers to make create_time column immutable';

commit;

`),
	},
	"migrations/02_oplog.down.sql": {
		name: "02_oplog.down.sql",
		bytes: []byte(`
begin;

drop table if exists oplog_entry cascade;

drop trigger if exists update_oplog_entry_update_time on oplog_entry;
drop trigger if exists update_oplog_entry_create_time on oplog_entry;

drop table if exists oplog_ticket cascade;

drop trigger if exists update_oplog_ticket_update_time on oplog_ticket;
drop trigger if exists update_oplog_ticket_create_time on oplog_ticket;

drop table if exists oplog_metadata cascade;

drop trigger if exists update_oplog_metadata_update_time on oplog_metadata;
drop trigger if exists update_oplog_metadata_create_time on oplog_metadata;

commit;
`),
	},
	"migrations/02_oplog.up.sql": {
		name: "02_oplog.up.sql",
		bytes: []byte(`
begin;

create table if not exists oplog_entry (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version text not null,
  aggregate_name text not null,
  "data" bytea not null
);

create trigger 
  update_time_column 
before 
update on oplog_entry 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_entry 
  for each row execute procedure immutable_create_time_func();

create table if not exists oplog_ticket (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  "name" text not null unique,
  "version" bigint not null
);

create trigger 
  update_time_column 
before 
update on oplog_ticket 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_ticket 
  for each row execute procedure immutable_create_time_func();

create table if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  entry_id bigint not null references oplog_entry(id) on delete cascade on update cascade,
  "key" text not null,
  value text null
);

create trigger 
  update_time_column 
before 
update on oplog_metadata 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_metadata 
  for each row execute procedure immutable_create_time_func();

create index if not exists idx_oplog_metatadata_key on oplog_metadata(key);

create index if not exists idx_oplog_metatadata_value on oplog_metadata(value);

insert into oplog_ticket (name, version)
values
  ('default', 1),
  ('iam_scope', 1),
  ('iam_user', 1),
  ('iam_auth_method', 1),
  ('iam_group', 1),
  ('iam_group_member_user', 1),
  ('iam_role', 1),
  ('iam_role_grant', 1),
  ('iam_role_group', 1),
  ('iam_role_user', 1),
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1);

commit;


`),
	},
	"migrations/03_db.down.sql": {
		name: "03_db.down.sql",
		bytes: []byte(`
begin;

drop table if exists db_test_user;
drop table if exists db_test_car;
drop table if exists db_test_rental;

drop trigger if exists update_db_test_user_update_time on db_test_user;
drop trigger if exists update_db_test_user_create_time on db_test_user;

drop trigger if exists update_db_test_car_update_time on db_test_car;
drop trigger if exists update_db_test_car_create_time on db_test_car;

drop trigger if exists update_db_test_rental_update_time on db_test_rental;
drop trigger if exists update_db_test_rental_create_time on db_test_rental;

commit;

`),
	},
	"migrations/03_db.up.sql": {
		name: "03_db.up.sql",
		bytes: []byte(`
begin;

-- create test tables used in the unit tests for the internal/db package
-- these tables (db_test_user, db_test_car, db_test_rental) are not part
-- of the watchtower domain model... they are simply used for testing the internal/db package
create table if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  phone_number text,
  email text
);

create trigger 
  update_time_column 
before 
update on db_test_user 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_user 
  for each row execute procedure immutable_create_time_func();

create table if not exists db_test_car (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger 
  update_time_column 
before 
update on db_test_car 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_car 
  for each row execute procedure immutable_create_time_func();

create table if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  user_id bigint not null references db_test_user(id),
  car_id bigint not null references db_test_car(id)
);

create trigger 
  update_time_column 
before 
update on db_test_rental 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_rental 
  for each row execute procedure immutable_create_time_func();


commit;

`),
	},
	"migrations/04_iam.down.sql": {
		name: "04_iam.down.sql",
		bytes: []byte(`
BEGIN;

drop table if exists iam_scope CASCADE;
drop trigger if exists iam_scope_insert;
drop function if exists iam_sub_scopes_func;

drop trigger if exists update_iam_scope_update_time on iam_scope;
drop trigger if exists update_iam_scope_create_time on iam_scope;

COMMIT;
`),
	},
	"migrations/04_iam.up.sql": {
		name: "04_iam.up.sql",
		bytes: []byte(`
begin;

create table iam_scope_type_enm (
  string text not null primary key check(string in ('unknown', 'organization', 'project'))
);

insert into iam_scope_type_enm (string)
values
  ('unknown'),
  ('organization'),
  ('project');

 
create table iam_scope (
    public_id wt_public_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    type text not null references iam_scope_type_enm(string) check(
      (
        type = 'organization'
        and parent_id = null
      )
      or (
        type = 'project'
        and parent_id is not null
      )
    ),
    description text,
    parent_id text references iam_scope(public_id) on delete cascade on update cascade
  );

create table iam_scope_organization (
    scope_id wt_public_id not null unique references iam_scope(public_id) on delete cascade on update cascade,
    name text unique,
    primary key(scope_id)
  );

create table iam_scope_project (
    scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
    parent_id wt_public_id not null references iam_scope_organization(scope_id) on delete cascade on update cascade,
    name text,
    unique(parent_id, name),
    primary key(scope_id, parent_id)
  );


create or replace function 
  iam_sub_scopes_func() 
  returns trigger
as $$ 
declare parent_type int;
begin 
  if new.type = 'organization' then
    insert into iam_scope_organization (scope_id, name)
    values
      (new.public_id, new.name);
    return new;
  end if;
  if new.type = 'project' then
    insert into iam_scope_project (scope_id, parent_id, name)
    values
      (new.public_id, new.parent_id, new.name);
    return new;
  end if;
  raise exception 'unknown scope type';
end;
$$ language plpgsql;


create trigger 
  iam_scope_insert
after
insert on iam_scope 
  for each row execute procedure iam_sub_scopes_func();


create or replace function 
  iam_immutable_scope_type_func() 
  returns trigger
as $$ 
declare parent_type int;
begin 
  if new.type != old.type then
    raise exception 'scope type cannot be updated';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger 
  iam_scope_update
before 
update on iam_scope 
  for each row execute procedure iam_immutable_scope_type_func();

create trigger 
  update_time_column 
before update on iam_scope 
  for each row execute procedure update_time_column();

create trigger 
  immutable_create_time
before
update on iam_scope 
  for each row execute procedure immutable_create_time_func();

commit;

`),
	},
}
