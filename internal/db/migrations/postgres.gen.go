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
drop domain wt_private_id;
drop domain wt_version;

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

create domain wt_private_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_private_id is
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
  ('auth_token', 1),
  ('default', 1),
  ('iam_scope', 1),
  ('iam_user', 1),
  ('iam_group', 1),
  ('iam_group_member_user', 1),
  ('iam_role', 1),
  ('iam_role_grant', 1),
  ('iam_group_role', 1),
  ('iam_user_role', 1),
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1),
  ('db_test_scooter', 1),
  ('auth_account', 1),
  ('iam_principal_role', 1);
  

commit;


`),
	},
	"migrations/03_db.down.sql": {
		name: "03_db.down.sql",
		bytes: []byte(`
begin;

drop table db_test_rental cascade;
drop table db_test_car cascade;
drop table db_test_user cascade;
drop table db_test_scooter cascade;

commit;

`),
	},
	"migrations/03_db.up.sql": {
		name: "03_db.up.sql",
		bytes: []byte(`
begin;

-- create test tables used in the unit tests for the internal/db package 
-- these tables (db_test_user, db_test_car, db_test_rental, db_test_scooter) are
-- not part of the watchtower domain model... they are simply used for testing
-- the internal/db package 
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


create table if not exists db_test_scooter (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  private_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger 
  update_time_column 
before 
update on db_test_scooter 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_scooter 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on db_test_scooter
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
drop table iam_group_role cascade;
drop table iam_user_role cascade;
drop table iam_role_grant cascade;
drop view iam_principal_role cascade;

drop function iam_sub_names cascade;
drop function iam_immutable_scope_type_func cascade;
drop function iam_sub_scopes_func cascade;
drop function iam_immutable_role cascade;
drop function iam_user_role_scope_check cascade;
drop function iam_group_role_scope_check cascade;

COMMIT;

`),
	},
	"migrations/06_iam.up.sql": {
		name: "06_iam.up.sql",
		bytes: []byte(`
begin;

create table iam_scope_type_enm (
  string text primary key check(string in ('unknown', 'organization', 'project'))
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
    public_id wt_public_id primary key,
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
    public_id wt_public_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
    unique(name, scope_id),
    disabled boolean not null default false,
    -- version allows optimistic locking of the role when modifying the role
    -- itself and when modifying dependent items like principal roles. 
    -- TODO (jlambert 6/2020) add before update trigger to automatically
    -- increment the version when needed.  This trigger can be addded when PR
    -- #126 is merged and update_version_column() is available.
    version bigint not null default 1,
    
    -- add unique index so a composite fk can be declared.
    unique(scope_id, public_id)
  );

-- Grants are immutable, which is enforced via the trigger below
create table iam_role_grant (
    create_time wt_timestamp,
    update_time wt_timestamp,
    role_id wt_public_id not null references iam_role(public_id) on delete cascade on update cascade,
    raw_grant text not null,
    canonical_grant text not null,
    primary key(role_id, canonical_grant)
  );

-- iam_immutable_role_grant() ensures that grants assigned to roles are immutable. 
create or replace function
  iam_immutable_role_grant()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    raise exception 'role grants are immutable';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger immutable_role_grant
before
update on iam_role_grant
  for each row execute procedure iam_immutable_role_grant();

create trigger 
  update_version_column
after update on iam_role
  for each row execute procedure update_version_column();
  
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
    disabled boolean not null default false,
    -- add unique index so a composite fk can be declared.
    unique(scope_id, public_id)
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
  
-- iam_user_role contains roles that have been assigned to users. Users can only
-- be assigned roles which are within its organization, or the role is within a project within its
-- organization. There's no way to declare this constraint, so it will be
-- maintained with a before insert trigger using iam_user_role_scope_check().
-- The rows in this table must be immutable after insert, which will be ensured
-- with a before update trigger using iam_immutable_role(). 
create table iam_user_role (
  create_time wt_timestamp,
  scope_id wt_public_id not null,
  role_id wt_public_id not null,
  principal_id wt_public_id not null references iam_user(public_id) on delete cascade on update cascade,
  primary key (role_id, principal_id),
  foreign key (scope_id, role_id)
    references iam_role(scope_id, public_id)
    on delete cascade
    on update cascade
  );

-- iam_group_role contains roles that have been assigned to groups. Groups can
-- only be assigned roles which are within its scope (organization or project)
-- and that integrity can be maintained with a foreign key. The rows in this
-- table must be immutable after insert, which will be ensured with a before
-- update trigger using iam_immutable_role().
create table iam_group_role (
  create_time wt_timestamp,
  scope_id wt_public_id not null,
  role_id wt_public_id not null,
  principal_id wt_public_id not null,
  primary key (role_id, principal_id),
  foreign key (scope_id, role_id)
    references iam_role(scope_id, public_id)
    on delete cascade
    on update cascade,
  foreign key (scope_id, principal_id)
    references iam_group(scope_id, public_id)
    on delete cascade
    on update cascade
  );

-- iam_principle_role provides a consolidated view all principal roles assigned
-- (user and group roles).
create view iam_principal_role as
select
  -- intentionally using * to specify the view which requires that the concrete role assignment tables match
  *, 'user' as type
from iam_user_role
union
select
  -- intentionally using * to specify the view which requires that the concrete role assignment tables match
  *, 'group' as type
from iam_group_role;

-- iam_user_role_scope_check() ensures that the user is only assigned roles
-- which are within its organization, or the role is within a project within its
-- organization. 
create or replace function 
  iam_user_role_scope_check() 
  returns trigger
as $$ 
declare cnt int;
begin
  select count(*) into cnt
  from iam_user 
  where 
    public_id = new.principal_id and 
  scope_id in(
    -- check to see if they have the same org scope
    select s.public_id 
      from iam_scope s, iam_role r 
      where s.public_id = r.scope_id and r.public_id = new.role_id and r.scope_id = new.scope_id
    union
    -- check to see if the role has a parent that's the same org
    select s.parent_id as public_id 
      from iam_role r, iam_scope s 
      where r.scope_id = s.public_id and r.public_id = new.role_id and r.scope_id = new.scope_id
  );
  if cnt = 0 then
    raise exception 'user and role do not belong to the same organization';
  end if;
  return new;
end;
$$ language plpgsql;

-- iam_immutable_role() ensures that roles assigned to principals are immutable. 
create or replace function
  iam_immutable_role()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    raise exception 'roles are immutable';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger iam_user_role_scope_check
before
insert on iam_user_role
  for each row execute procedure iam_user_role_scope_check();

create trigger immutable_role
before
update on iam_user_role
  for each row execute procedure iam_immutable_role();

create trigger 
  immutable_create_time
before
update on iam_user_role
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on iam_user_role
  for each row execute procedure default_create_time();

create trigger immutable_role
before
update on iam_group_role
  for each row execute procedure iam_immutable_role();

create trigger 
  immutable_create_time
before
update on iam_group_role
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on iam_group_role
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
	"migrations/08_iam.down.sql": {
		name: "08_iam.down.sql",
		bytes: []byte(`
BEGIN;

drop table if exists iam_auth_method cascade;
drop table if exists iam_group_member_type_enm cascade;
drop table if exists iam_group cascade cascade;
drop table if exists iam_group_member_user cascade;
drop view if exists iam_group_member;
drop table if exists iam_auth_method_type_enm cascade;
drop table if exists iam_action_enm cascade;
drop view if exists iam_assigned_role;


COMMIT;
`),
	},
	"migrations/08_iam.up.sql": {
		name: "08_iam.up.sql",
		bytes: []byte(`
BEGIN;

create table iam_group_member_user (
  create_time wt_timestamp,
  group_id wt_public_id references iam_group(public_id) on delete cascade on update cascade,
  member_id wt_public_id references iam_user(public_id) on delete cascade on update cascade,
  primary key (group_id, member_id)
);


-- iam_group_member_user_scope_check() ensures that the user is only assigned
-- groups which are within its organization, or the group is within a project
-- within its organization. 
create or replace function 
  iam_group_member_user_scope_check() 
  returns trigger
as $$ 
declare cnt int;
begin
  select count(*) into cnt
  from iam_user 
  where 
    public_id = new.member_id and 
  scope_id in(
    -- check to see if they have the same org scope
    select s.public_id 
      from iam_scope s, iam_group g 
      where s.public_id = g.scope_id and g.public_id = new.group_id 
    union
    -- check to see if the role has a parent that's the same org
    select s.parent_id as public_id 
      from iam_group g, iam_scope s 
      where g.scope_id = s.public_id and g.public_id = new.role_id 
  );
  if cnt = 0 then
    raise exception 'user and group do not belong to the same organization';
  end if;
  return new;
end;
$$ language plpgsql;


CREATE TABLE iam_auth_method (
    public_id wt_public_id primary key, 
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id NOT NULL REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE,
    unique(name, scope_id),
    disabled BOOLEAN NOT NULL default FALSE,
    type text NOT NULL
  );

CREATE TABLE iam_auth_method_type_enm (
    string text primary key CHECK(string IN ('unknown', 'password', 'oidc'))
  );
INSERT INTO iam_auth_method_type_enm (string)
values
  ('unknown'),
  ('password'),
  ('oidc');
ALTER TABLE iam_auth_method
ADD
  FOREIGN KEY (type) REFERENCES iam_auth_method_type_enm(string);

CREATE TABLE iam_action_enm (
    string text primary key CHECK(
      string IN (
        'unknown',
        'list',
        'create',
        'update',
        'read',
        'delete',
        'authenticate',
        'all',
        'connect',
        'add-grants',
        'delete-grants',
        'set-grants'
      )
    )
  );

INSERT INTO iam_action_enm (string)
values
  ('unknown'),
  ('list'),
  ('create'),
  ('update'),
  ('read'),
  ('delete'),
  ('authenticate'),
  ('all'),
  ('connect'),
  ('add-grants'),
  ('delete-grants'),
  ('set-grants');

  COMMIT;

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
	"migrations/11_auth_token.down.sql": {
		name: "11_auth_token.down.sql",
		bytes: []byte(`
begin;

  drop view auth_token_account cascade;
  drop table auth_token cascade;

  drop function update_last_access_time cascade;
  drop function immutable_auth_token_columns cascade;
  drop function expire_time_not_older_than_token cascade;

commit;

`),
	},
	"migrations/11_auth_token.up.sql": {
		name: "11_auth_token.up.sql",
		bytes: []byte(`
begin;

  -- an auth token belongs to 1 and only 1 auth account
  -- an auth account can have 0 to many auth tokens
  create table auth_token (
    public_id wt_public_id primary key,
    token bytea not null unique,
    auth_account_id wt_public_id not null
      references auth_account(public_id)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    -- This column is not updated every time this auth token is accessed.
    -- It is updated after X minutes from the last time it was updated on
    -- a per row basis.
    approximate_last_access_time wt_timestamp
      check(
        approximate_last_access_time <= expiration_time
      ),
    expiration_time wt_timestamp
      check(
        create_time <= expiration_time
      )
  );

  create view auth_token_account as
        select at.public_id,
               at.token,
               at.auth_account_id,
               at.create_time,
               at.update_time,
               at.approximate_last_access_time,
               at.expiration_time,
               aa.scope_id,
               aa.iam_user_id,
               aa.auth_method_id
          from auth_token as at
    inner join auth_account as aa
            on at.auth_account_id = aa.public_id;

  create or replace function
    update_last_access_time()
    returns trigger
  as $$
  begin
    if new.approximate_last_access_time is distinct from old.approximate_last_access_time then
      new.approximate_last_access_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    update_last_access_time()
  is
    'function used in before update triggers to properly set last_access_time columns';

  create or replace function
    immutable_auth_token_columns()
    returns trigger
  as $$
  begin
    if new.auth_account_id is distinct from old.auth_account_id then
      raise exception 'auth_account_id is read-only';
    end if;
    if new.token is distinct from old.token then
      raise exception 'token is read-only';
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    immutable_auth_token_columns()
  is
    'function used in before update triggers to make specific columns immutable';

  -- This allows the expiration to be calculated on the server side and still hold the constraint that
  -- the expiration time cant be before the creation time of the auth token.
  create or replace function
    expire_time_not_older_than_token()
    returns trigger
  as $$
  begin
    if new.expiration_time < new.create_time then
      new.expiration_time = new.create_time;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
      expire_time_not_older_than_token()
  is
    'function used in before insert triggers to ensure expiration time is not older than create time';

  create trigger
    default_create_time_column
  before insert on auth_token
    for each row execute procedure default_create_time();

  create trigger
    expire_time_not_older_than_token
  before insert on auth_token
    for each row execute procedure expire_time_not_older_than_token();

  create trigger
    update_time_column
  before update on auth_token
    for each row execute procedure update_time_column();

  create trigger
    update_last_access_time
  before update on auth_token
    for each row execute procedure update_last_access_time();

  create trigger
    immutable_create_time
  before update on auth_token
    for each row execute procedure immutable_create_time_func();

  create trigger
    immutable_auth_token_columns
  before update on auth_token
    for each row execute procedure immutable_auth_token_columns();

commit;

`),
	},
}
