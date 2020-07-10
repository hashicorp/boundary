begin;

create table iam_scope_type_enm (
  string text not null primary key check(string in ('unknown', 'global', 'organization', 'project'))
);

insert into iam_scope_type_enm (string)
values
  ('unknown'),
  ('global'),
  ('organization'),
  ('project');


create or replace function
  iam_immutable_scope_id_func()
  returns trigger
as $$
begin
  if new.scope_id is distinct from old.scope_id then
    raise exception 'scope_id cannot be set to %', new.scope_id;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  iam_immutable_scope_id_func()
is
  'function used in before update triggers to make scope_id column is immutable';

create table iam_scope (
    public_id wt_scope_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    type text not null references iam_scope_type_enm(string) check(
      (
        type = 'global'
        and parent_id is null
      )
      or (
        type = 'organization'
        and parent_id = 'global'
      )
      or (
        type = 'project'
        and parent_id is not null
        and parent_id != 'global'
      )
    ),
    description text,
    parent_id text references iam_scope(public_id) on delete cascade on update cascade
  );

create table iam_scope_global (
    scope_id wt_scope_id primary key
      references iam_scope(public_id)
      on delete cascade
      on update cascade
      check(
        scope_id = 'global'
      ),
    name text unique
);

create table iam_scope_organization (
  scope_id wt_scope_id primary key
    references iam_scope(public_id)
    on delete cascade
    on update cascade,
  parent_id wt_scope_id not null
    references iam_scope_global(scope_id)
    on delete cascade
    on update cascade,
  name text,
  unique (parent_id, name)
);

create table iam_scope_project (
    scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
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
  if new.type = 'global' then
    insert into iam_scope_global (scope_id, name)
    values
      (new.public_id, new.name);
    return new;
  end if;
  if new.type = 'organization' then
    insert into iam_scope_organization (scope_id, parent_id, name)
    values
      (new.public_id, new.parent_id, new.name);
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
  disallow_global_scope_deletion()
  returns trigger
as $$
begin
  if old.type = 'global' then
    raise exception 'deletion of global scope not allowed';
  end if;
  return old;
end;
$$ language plpgsql;

create trigger
  iam_scope_disallow_global_deletion
before
delete on iam_scope
  for each row execute procedure disallow_global_scope_deletion();

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
    if new.type = 'global' then
      update iam_scope_global set name = new.name where scope_id = old.public_id;
      return new;
    end if;
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

insert into iam_scope (public_id, name, type, description)
  values ('global', 'global', 'global', 'Global Scope');


create table iam_user (
    public_id wt_user_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
    unique(name, scope_id),
    disabled boolean not null default false,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(scope_id, public_id)
  );

create or replace function
  user_scope_id_valid()
  returns trigger
as $$
begin
  perform from iam_scope where public_id = new.scope_id and type in ('global', 'organization');
  if not found then
    raise exception 'invalid scope type for user creation';
  end if;
  return new;
end;
$$ language plpgsql;

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
  if role_scope_type = 'global' then
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

create or replace function
  disallow_iam_anon_auth_deletion()
  returns trigger
as $$
begin
  if old.public_id = 'u_anon' then
    raise exception 'deletion of anonymous user not allowed';
  end if;
  if old.public_id = 'u_auth' then
    raise exception 'deletion of authenticated user not allowed';
  end if;
  return old;
end;
$$ language plpgsql;

create trigger
  ensure_user_scope_id_valid
before
insert or update on iam_user
  for each row execute procedure user_scope_id_valid();

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

create trigger immutable_scope_id_user
before
update on iam_user
  for each row execute procedure iam_immutable_scope_id_func();

create trigger
  iam_user_disallow_anon_auth_deletion
before
delete on iam_user
  for each row execute procedure disallow_iam_anon_auth_deletion();

-- TODO: Do we want to disallow changing the name or description?
insert into iam_user (public_id, name, description, scope_id)
  values ('u_anon', 'anonymous', 'The anonymous user matches any request, whether authenticated or not', 'global');

insert into iam_user (public_id, name, description, scope_id)
  values ('u_auth', 'authenticated', 'The authenticated user matches any user that has a valid token', 'global');

create table iam_role (
    public_id wt_public_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
    grant_scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
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
    role_id wt_public_id -- pk
      references iam_role(public_id)
      on delete cascade
      on update cascade,
    canonical_grant text -- pk
      check(
        length(trim(canonical_grant)) > 0
      ),
    raw_grant text not null
      check(
        length(trim(raw_grant)) > 0
      ),
    primary key(role_id, canonical_grant)
  );

-- iam_immutable_role_grant() ensures that grants assigned to roles are immutable. 
create or replace function
  iam_immutable_role_grant()
  returns trigger
as $$
begin
  raise exception 'role grants are immutable';
end;
$$ language plpgsql;

create trigger immutable_role_grant
before
update on iam_role_grant
  for each row execute procedure iam_immutable_role_grant();
  
create trigger
  default_create_time_column
before
insert on iam_role_grant
  for each row execute procedure default_create_time();

-- prefix a_ to make this trigger run before ensure_grant_scope_id_valid
create trigger a_immutable_scope_id
before
update on iam_role
  for each row execute procedure iam_immutable_scope_id_func();

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
    scope_id wt_scope_id not null references iam_scope(public_id) on delete cascade on update cascade,
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

create trigger immutable_scope_id_group
before
update on iam_group
  for each row execute procedure iam_immutable_scope_id_func();

-- iam_user_role contains roles that have been assigned to users. Users can be
-- from any scope. The rows in this table must be immutable after insert, which
-- will be ensured with a before update trigger using iam_immutable_role(). 
create table iam_user_role (
  create_time wt_timestamp,
  role_id wt_public_id
    references iam_role(public_id)
    on delete cascade
    on update cascade,
  principal_id wt_user_id 
    references iam_user(public_id)
    on delete cascade
    on update cascade,
  primary key (role_id, principal_id)
  );

-- iam_group_role contains roles that have been assigned to groups. 
-- Groups can be from any scope. The rows in this table must be immutable after
-- insert, which will be ensured with a before update trigger using
-- iam_immutable_role(). 
create table iam_group_role (
  create_time wt_timestamp,
  role_id wt_public_id
    references iam_role(public_id)
    on delete cascade
    on update cascade,
  principal_id wt_public_id 
    references iam_group(public_id)
    on delete cascade
    on update cascade,
  primary key (role_id, principal_id)
  );

-- get_scoped_principal_id is used by the iam_principle_role view as a convient
-- way to create <scope_id>:<principal_id> to reference principals from
-- other scopes than the role's scope. 
create or replace function get_scoped_principal_id(role_scope text, principal_scope text, principal_id text) returns text 
as $$
begin
	if role_scope = principal_scope then
		return principal_id;
	end if;
	return principal_scope || ':' || principal_id;
end;
$$ language plpgsql;

-- iam_principle_role provides a consolidated view all principal roles assigned
-- (user and group roles).
create view iam_principal_role as
select 
	ur.create_time, 
	ur.principal_id,
	ur.role_id,
	u.scope_id as principal_scope_id, 
	r.scope_id as role_scope_id,
	get_scoped_principal_id(r.scope_id, u.scope_id, ur.principal_id) as scoped_principal_id,
	'user' as type
from 	
	iam_user_role ur, 
	iam_role r,
	iam_user u
where
	ur.role_id = r.public_id and 
	u.public_id = ur.principal_id
union 
select 
	gr.create_time, 
	gr.principal_id,
	gr.role_id,
	g.scope_id as principal_scope_id, 
	r.scope_id as role_scope_id,
	get_scoped_principal_id(r.scope_id, g.scope_id, gr.principal_id) as scoped_principal_id,
	'group' as type
from 	
	iam_group_role gr, 
	iam_role r,
	iam_group g
where
	gr.role_id = r.public_id and 
	g.public_id = gr.principal_id;

-- iam_immutable_role() ensures that roles assigned to principals are immutable. 
create or replace function
  iam_immutable_role()
  returns trigger
as $$
begin
    raise exception 'roles are immutable';
end;
$$ language plpgsql;

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
