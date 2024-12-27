begin;

-- base table for iam_role

create table iam_role_global_grant_scope_enm
(
  name text not null primary key
    constraint only_predefined_scope_types_allowed
      check (
        name in ('descendants', 'children', 'individual')
      )
);

insert into iam_role_global_grant_scope_enm (name)
values 
  ('descendants'),
  ('children'),
  ('individual');

create or replace function insert_role_subtype() returns trigger
as $$
begin
  insert into iam_role
    (public_id, scope_id)
  values
    (new.public_id, new.scope_id);
  return new;
end;
$$ language plpgsql;
comment on function insert_role_subtype() is
  'insert_role_subtype inserts a role to the appropriate subtype table';



-- global iam_role must have a scope_id of global
create table iam_role_global
(
  public_id             wt_role_id not null primary key
    references iam_role (public_id)
      on delete cascade
      on update cascade,
  scope_id              wt_scope_id
    references iam_scope_global (scope_id)
      on delete cascade
      on update cascade,
  name                  text,
  description           text,
  grant_this_role_scope boolean    not null,
  grant_scope           text
    references iam_role_global_grant_scope_enm (name)
      on delete restrict
      on update cascade,
  version               wt_version,
  unique (public_id, grant_scope)
);

create trigger insert_role_subtype before insert on iam_role_global
  for each row execute procedure insert_role_subtype();

create table iam_role_global_individual_grant_scope
(
  role_id     wt_role_id
    references iam_role_global (public_id)
      on delete cascade
      on update cascade
  -- grant_scope is used for constraint checking.
  -- This restricts the grant_scope to be 'individual'
  -- and since it is also a foreign key to the iam_role_global
  -- grant_scope, it ensures that iam_role_global is set to 'individual'
  -- if this table is populated for the corresponding role.
  ,
  grant_scope text
    constraint only_individual_grant_scope_allowed
      check (grant_scope = 'individual'),
  scope_id    wt_scope_id
    references iam_scope (public_id)
      on delete cascade
      on update cascade
    constraint not_global_scope
      check (scope_id != 'global'),
  foreign key (role_id, grant_scope)
    references iam_role_global (public_id, grant_scope)
);

create table iam_role_org_grant_scope_enm
(
  name text not null primary key
    constraint only_predefined_scope_types_allowed
      check (
        name in (
          'children', 
          'individual'
        )
      )
);

insert into iam_role_org_grant_scope_enm (name)
values
  ('children'), 
  ('individual');

create table iam_role_org
(
  public_id             wt_role_id not null primary key
    references iam_role (public_id)
      on delete cascade
      on update cascade,
  scope_id              wt_scope_id
    references iam_scope_org (scope_id)
      on delete cascade
      on update cascade,
  name                  text,
  description           text,
  grant_this_role_scope boolean    not null,
  grant_scope           text
    references iam_role_org_grant_scope_enm (name)
      on delete restrict
      on update cascade,
  version               wt_version,
  unique (public_id, grant_scope)
);

create trigger insert_role_subtype before insert on iam_role_org
  for each row execute procedure insert_role_subtype();

create table iam_role_org_individual_grant_scope
(
  role_id     wt_role_id
    references iam_role_org (public_id)
      on delete cascade
      on update cascade
  -- grant_scope is used for constraint checking.
  -- This restricts the grant_scope to be 'individual'
  -- and since it is also a foreign key to the iam_role_org
  -- grant_scope, it ensures that iam_role_org is set to 'individual'
  -- if this table is populated for the corresponding role.
  ,
  grant_scope text
    constraint only_individual_grant_scope_allowed
      check (grant_scope = 'individual'),
  scope_id    wt_scope_id
    references iam_scope_project (scope_id)
      -- TODO: ensure the project's parent is the role's scope.
      on delete cascade
      on update cascade,
  foreign key (role_id, grant_scope)
      references iam_role_org (public_id, grant_scope)
);

create table iam_role_project
(
  public_id   wt_role_id  not null primary key
    references iam_role (public_id)
      on delete cascade
      on update cascade,
  scope_id    wt_scope_id not null
    references iam_scope_project (scope_id)
      on delete cascade
      on update cascade,
  name        text,
  description text,
  version     wt_version
);
create trigger insert_role_subtype before insert on iam_role_project
  for each row execute procedure insert_role_subtype();

create table resource_enm
(
  string text not null primary key
);

insert into resource_enm (string)
values 
  ('*'),
  ('unknown'),
  ('scope'),
  ('user'),
  ('group'),
  ('role'),
  ('auth-method'),
  ('account'),
  ('auth-token'),
  ('host-catalog'),
  ('host-set'),
  ('host'),
  ('target'),
  ('controller'),
  ('worker'),
  ('session'),
  ('session-recording'),
  ('managed-group'),
  ('credential-store'),
  ('credential-library'),
  ('credential'),
  ('storage-bucket'),
  ('policy'),
  ('billing'),
  ('alias');

-- iam_grant is the root table for a grant value object.
-- A grant can only reference a single resource, including the special
-- strings "*" to indicate "all" resources, and "unknown" when no resource is set.
-- The set of actions that are included in the grant
-- get associated with the grant in the iam_grant_action
-- table. We could potentially have a trigger function on insert
-- that parses the grant and inserts the appropriate rows into the other tables.
-- This should be immutable, and there isn't really a need to delete them.
create table iam_grant
(
  canonical_grant text not null primary key,
  resource        text not null
    references resource_enm (string)
      on delete restrict
      on update cascade
);
create index iam_grant_resource_ix
  on iam_grant (resource);

create function set_resource() returns trigger
as $$
declare resource text[];
begin
  select regexp_matches(new.canonical_grant, 'type=([^;]+);')
  into resource;
  if resource is null then
    new.resource = 'unknown';
  else
    new.resource = resource[1];
  end if;
  return new;
end
$$ language plpgsql;


create trigger set_resource before insert on iam_grant
  for each row execute procedure set_resource();

create index iam_role_grant_canonical_grant_ix
  on iam_role_grant (canonical_grant);

create function upsert_canonical_grant() returns trigger
as $$
begin
  insert into iam_grant
    (canonical_grant)
  values 
    (new.canonical_grant)
  on conflict do nothing;
  return new;
end
$$ language plpgsql;

create trigger upsert_canonical_grant before insert on iam_role_grant
  for each row execute procedure upsert_canonical_grant();

commit;