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

drop function default_create_time;
drop function immutable_create_time_func;
drop function update_time_column;
drop function update_version_column;

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
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = old.create_time;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  immutable_create_time_func()
is
  'function used in before update triggers to make create_time column immutable';
  
create or replace function
  default_create_time()
  returns trigger
as $$
begin
  if new.create_time is distinct from now() then
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = now();
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  default_create_time()
is
  'function used in before insert triggers to set create_time column to now';


create domain wt_version as bigint
default 1 
check(
  value > 0
);
comment on domain wt_version is
'standard column for row version';

-- update_version_column() will increment the version column whenever row data
-- is updated and should only be used in an update after trigger.  This function
-- will overwrite any explicit updates to the version column. 
create or replace function
  update_version_column()
  returns trigger
as $$
begin
  if pg_trigger_depth() = 1 then
    if row(new.*) is distinct from row(old.*) then
      execute format('update %I set version = $1 where public_id = $2', tg_relid::regclass) using old.version+1, new.public_id;
      new.version = old.version + 1;
      return new;
    end if;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  update_version_column()
is
  'function used in after update triggers to properly set version columns';

commit;

`),
	},
	"migrations/02_oplog.down.sql": {
		name: "02_oplog.down.sql",
		bytes: []byte(`
begin;

drop table oplog_metadata cascade;
drop table oplog_ticket cascade;
drop table oplog_entry cascade;

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

create trigger 
  default_create_time_column
before
insert on oplog_entry
  for each row execute procedure default_create_time();

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

create trigger 
  default_create_time_column
before
insert on oplog_ticket
  for each row execute procedure default_create_time();

create table if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
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

create trigger 
  default_create_time_column
before
insert on oplog_metadata 
  for each row execute procedure default_create_time();

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

drop table db_test_rental;
drop table db_test_car;
drop table db_test_user;

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
  email text,
  version wt_version
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

create trigger 
  default_create_time_column
before
insert on db_test_user 
  for each row execute procedure default_create_time();

create trigger 
  update_version_column
after update on db_test_user
  for each row execute procedure update_version_column();
  
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

create trigger 
  default_create_time_column
before
insert on db_test_car
  for each row execute procedure default_create_time();

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

create trigger 
  default_create_time_column
before
insert on db_test_rental
  for each row execute procedure default_create_time();


commit;

`),
	},
	"migrations/06_iam.down.sql": {
		name: "06_iam.down.sql",
		bytes: []byte(`
BEGIN;

drop table iam_group cascade;
drop table iam_user cascade;
drop table iam_scope_project cascade;
drop table iam_scope_organization cascade;
drop table iam_scope cascade;
drop table iam_scope_type_enm cascade;
drop table iam_role cascade;


drop function iam_sub_names cascade;
drop function iam_immutable_scope_type_func cascade;
drop function iam_sub_scopes_func cascade;

COMMIT;

`),
	},
	"migrations/06_iam.up.sql": {
		name: "06_iam.up.sql",
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
  
create trigger 
  default_create_time_column
before
insert on iam_scope
  for each row execute procedure default_create_time();


-- iam_sub_names will allow us to enforce the different name constraints for
-- organizations and projects via a before update trigger on the iam_scope
-- table. 
create or replace function 
  iam_sub_names() 
  returns trigger
as $$ 
begin 
  if new.name != old.name then
    if new.type = 'organization' then
      update iam_scope_organization set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    if new.type = 'project' then
      update iam_scope_project set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    raise exception 'unknown scope type';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger 
  iam_sub_names 
before 
update on iam_scope
  for each row execute procedure iam_sub_names();


create table iam_user (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id not null references iam_scope_organization(scope_id) on delete cascade on update cascade,
    unique(name, scope_id),
    disabled boolean not null default false,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(scope_id, public_id)
  );

create trigger 
  update_time_column 
before update on iam_user 
  for each row execute procedure update_time_column();

create trigger 
  immutable_create_time
before
update on iam_user 
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on iam_user
  for each row execute procedure default_create_time();

create table iam_role (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
    unique(name, scope_id),
    disabled boolean not null default false
  );

create trigger 
  update_time_column 
before update on iam_role
  for each row execute procedure update_time_column();

create trigger 
  immutable_create_time
before
update on iam_role
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on iam_role
  for each row execute procedure default_create_time();

create table iam_group (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
    unique(name, scope_id),
    disabled boolean not null default false
  );
  
create trigger 
  update_time_column 
before update on iam_group
  for each row execute procedure update_time_column();

create trigger 
  immutable_create_time
before
update on iam_group
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on iam_group
  for each row execute procedure default_create_time();
  
commit;

`),
	},
	"migrations/07_auth.down.sql": {
		name: "07_auth.down.sql",
		bytes: []byte(`
begin;

  drop function insert_auth_account_subtype;
  drop function insert_auth_method_subtype;

  drop table auth_account cascade;
  drop table auth_method cascade;

commit;

`),
	},
	"migrations/07_auth.up.sql": {
		name: "07_auth.up.sql",
		bytes: []byte(`
begin;

  -- Design influenced by:
  -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
  --
  -- iam_scope ←─────  auth_method
  --    ↑                  ↑
  -- iam_user  ←─────  auth_account

  -- base table for auth methods
  create table auth_method (
    public_id wt_public_id primary key,
    scope_id wt_public_id not null
      references iam_scope(public_id)
      on delete cascade
      on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(scope_id, public_id)
  );


  -- base table for auth accounts
  create table auth_account (
    public_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    scope_id wt_public_id not null,
    iam_user_id wt_public_id,
    foreign key (scope_id, auth_method_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, iam_user_id)
      references iam_user (scope_id, public_id)
      on delete set null
      on update cascade,
    unique(scope_id, auth_method_id, public_id)
  );


  create or replace function
    insert_auth_method_subtype()
    returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function
    insert_auth_account_subtype()
    returns trigger
  as $$
  begin
    insert into auth_account
      (public_id, auth_method_id, scope_id)
    values
      (new.public_id, new.auth_method_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

commit;

`),
	},
	"migrations/10_static_host.down.sql": {
		name: "10_static_host.down.sql",
		bytes: []byte(`
begin;

  drop table static_host_set_member cascade;
  drop table static_host_set cascade;
  drop table static_host cascade;
  drop table static_host_catalog cascade;

commit;

`),
	},
	"migrations/10_static_host.up.sql": {
		name: "10_static_host.up.sql",
		bytes: []byte(`
begin;

  create table static_host_catalog (
    public_id wt_public_id primary key,
    scope_id wt_public_id not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(scope_id, name)
  );

  create trigger
    update_time_column
  before update on static_host_catalog
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on static_host_catalog
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on static_host_catalog
    for each row execute procedure default_create_time();

  create table static_host (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    address text not null
    check(
      length(trim(address)) > 7
      and
      length(trim(address)) < 256
    ),
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(static_host_catalog_id, name)
  );

  create trigger
    update_time_column
  before update on static_host
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on static_host
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on static_host
    for each row execute procedure default_create_time();

  create table static_host_set (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(static_host_catalog_id, name)
  );

  create trigger
    update_time_column
  before update on static_host_set
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on static_host_set
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on static_host_set
    for each row execute procedure default_create_time();

  create table static_host_set_member (
    static_host_set_id wt_public_id
      references static_host_set (public_id)
      on delete cascade
      on update cascade,
    static_host_id wt_public_id
      references static_host (public_id)
      on delete cascade
      on update cascade,
    primary key(static_host_set_id, static_host_id)
  );

  insert into oplog_ticket (name, version)
  values
    ('static_host_catalog', 1),
    ('static_host', 1),
    ('static_host_set', 1),
    ('static_host_set_member', 1);

commit;

`),
	},
}
