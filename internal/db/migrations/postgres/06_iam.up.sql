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

create or replace function
  grant_scope_id_valid()
  returns trigger
as $$
declare parent_scope_id text;
declare role_scope_type text;
begin
  -- There is a not-null constraint so ensure that if the value passed in is
  -- empty we simply set to the scope ID
  if new.grant_scope_id = '' or new.grant_scope_id is null then
    new.grant_scope_id = new.scope_id;
  end if;
  -- If the scopes match, it's allowed
  if new.grant_scope_id = new.scope_id then
    return new;
  end if;
  -- Fetch the type of scope
  select isc.type from iam_scope isc where isc.public_id = new.scope_id into role_scope_type;
  -- Always allowed
  if role_scope_type = 'msp' then
    return new;
  end if;
  -- Never allowed; the case where it's set to the same scope ID as the project
  -- itself is covered above
  if role_scope_type = 'project' then
    raise exception 'invalid to set grant_scope_id to non-same scope_id when role scope type is project';
  end if;
  if role_scope_type = 'organization' then
    -- Look up the parent scope ID for the scope ID given
    select isc.parent_id from iam_scope isc where isc.public_id = new.grant_scope_id into parent_scope_id;
    -- Allow iff the grant scope ID's parent matches the role's scope ID; that
    -- is, match if the role belongs to a direct child scope of this
    -- organization
    if parent_scope_id = new.scope_id then
      return new;
    end if;
    raise exception 'grant_scope_id is not a child project of the role scope';
  end if;
  raise exception 'unknown scope type';
end;
$$ language plpgsql;

create table iam_role (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
    grant_scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
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

create trigger
  ensure_grant_scope_id_valid
before
insert or update on iam_role
  for each row execute procedure grant_scope_id_valid();

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
