create
or replace function create_constraint_if_not_exists (
  t_name text,
  c_name text,
  constraint_sql text
) returns void AS $$ begin -- Look for our constraint
if not exists (
  select
    constraint_name
  from information_schema.constraint_column_usage
  where
    table_name = t_name
    and constraint_name = c_name
) then execute 'ALTER TABLE ' || t_name || ' ADD CONSTRAINT ' || c_name || ' ' || constraint_sql;
end if;
end;
$$ language 'plpgsql';
--
-- define the iam_auth_method_type_enm lookup table
--
CREATE TABLE if not exists iam_scope_type_enm (
  string text NOT NULL primary key CHECK(string IN ('unknown', 'organization', 'project'))
);
INSERT INTO iam_scope_type_enm (string)
values
  ('unknown');
INSERT INTO iam_scope_type_enm (string)
values
  ('organization');
INSERT INTO iam_scope_type_enm (string)
values
  ('project');
CREATE TABLE if not exists iam_scope (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    public_id text NOT NULL UNIQUE,
    friendly_name text UNIQUE,
    type text NOT NULL REFERENCES iam_scope_type_enm(string) CHECK(
      (
        type = 'organization'
        and parent_id = NULL
      )
      or (
        type = 'project'
        and parent_id IS NOT NULL
      )
    ),
    parent_id bigint REFERENCES iam_scope(id) ON DELETE CASCADE ON UPDATE CASCADE,
    disabled BOOLEAN NOT NULL default FALSE
  );
create table if not exists iam_scope_organization (
    scope_id bigint NOT NULL UNIQUE REFERENCES iam_scope(id) ON DELETE CASCADE ON UPDATE CASCADE
  );
create table if not exists iam_scope_project (
    scope_id bigint REFERENCES iam_scope(id) ON DELETE CASCADE ON UPDATE CASCADE,
    parent_id bigint REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE
  );
CREATE
  OR REPLACE FUNCTION iam_sub_scopes_func() RETURNS TRIGGER
SET SCHEMA
  'public' LANGUAGE plpgsql AS $$ DECLARE parent_type INT;
BEGIN IF new.type = 'organization' THEN
insert into iam_scope_organization (scope_id)
values
  (new.id);
return NEW;
END IF;
IF new.type = 'project' THEN
insert into iam_scope_project (scope_id, parent_id)
values
  (new.id, new.parent_id);
return NEW;
END IF;
RAISE EXCEPTION 'unknown scope type';
END;
$$;
CREATE TRIGGER iam_scope_insert
AFTER
insert ON iam_scope FOR EACH ROW EXECUTE PROCEDURE iam_sub_scopes_func();
CREATE TABLE if not exists iam_user (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    name text NOT NULL,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope_organization(scope_id),
    disabled BOOLEAN NOT NULL default FALSE
  );
CREATE TABLE if not exists iam_auth_method (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope_organization(scope_id),
    disabled BOOLEAN NOT NULL default FALSE,
    type text NOT NULL
  );
CREATE TABLE if not exists iam_role (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    description text,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    disabled BOOLEAN NOT NULL default FALSE
  );
--
  -- define the iam_group_member_type_enm lookup table
  --
  CREATE TABLE if not exists iam_group_member_type_enm (
    string text NOT NULL primary key CHECK(string IN ('unknown', 'user'))
  );
INSERT INTO iam_group_member_type_enm (string)
values
  ('unknown');
INSERT INTO iam_group_member_type_enm (string)
values
  ('user');
CREATE TABLE if not exists iam_group (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    description text,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    disabled BOOLEAN NOT NULL default FALSE
  );
CREATE TABLE if not exists iam_group_member_user (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    group_id bigint NOT NULL REFERENCES iam_group(id),
    member_id bigint NOT NULL REFERENCES iam_user(id),
    type text NOT NULL REFERENCES iam_group_member_type_enm(string) check(type = 'user')
  );
CREATE VIEW iam_group_member AS
SELECT
  *
FROM iam_group_member_user;
--
  -- define the iam_auth_method_type_enm lookup table
  --
  CREATE TABLE if not exists iam_auth_method_type_enm (
    string text NOT NULL primary key CHECK(string IN ('unknown', 'userpass', 'oidc'))
  );
INSERT INTO iam_auth_method_type_enm (string)
values
  ('unknown');
INSERT INTO iam_auth_method_type_enm (string)
values
  ('userpass');
INSERT INTO iam_auth_method_type_enm (string)
values
  ('oidc');
ALTER TABLE iam_auth_method
ADD
  FOREIGN KEY (type) REFERENCES iam_auth_method_type_enm(string);
--
  -- define the iam_action_emn lookup table
  --
  CREATE TABLE if not exists iam_action_enm (
    string text NOT NULL primary key CHECK(
      string IN (
        'unknown',
        'list',
        'create',
        'update',
        'edit',
        'delete',
        'authen'
      )
    )
  );
INSERT INTO iam_action_enm (string)
values
  ('unknown');
INSERT INTO iam_action_enm (string)
values
  ('list');
INSERT INTO iam_action_enm (string)
values
  ('create');
INSERT INTO iam_action_enm (string)
values
  ('update');
INSERT INTO iam_action_enm (string)
values
  ('edit');
INSERT INTO iam_action_enm (string)
values
  ('delete');
INSERT INTO iam_action_enm (string)
values
  ('authen');
--
  -- define the iam_role_type_enm lookup table
  --
  CREATE TABLE if not exists iam_role_type_enm (
    id smallint NOT NULL primary key,
    string text NOT NULL UNIQUE
  );
INSERT INTO iam_role_type_enm (id, string)
values
  (0, 'unknown');
INSERT INTO iam_role_type_enm (id, string)
values
  (1, 'user');
INSERT INTO iam_role_type_enm (id, string)
values
  (2, 'group');
ALTER TABLE iam_role_type_enm
ADD
  CONSTRAINT iam_role_type_enm_between_chk CHECK (
    id BETWEEN 0
    AND 3
  );
CREATE TABLE if not exists iam_role_user (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    role_id bigint NOT NULL REFERENCES iam_role(id),
    principal_id bigint NOT NULL REFERENCES iam_user(id),
    type int NOT NULL REFERENCES iam_role_type_enm(id) CHECK(type = 1)
  );
CREATE TABLE if not exists iam_role_group (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    role_id bigint NOT NULL REFERENCES iam_role(id),
    principal_id bigint NOT NULL REFERENCES iam_group(id),
    type int NOT NULL REFERENCES iam_role_type_enm(id) CHECK(type = 2)
  );
CREATE VIEW iam_assigned_role_vw AS
SELECT
  *
FROM iam_role_user
UNION
select
  *
from iam_role_group;
CREATE TABLE if not exists iam_role_grant (
    id bigint generated always as identity primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    public_id text not null UNIQUE,
    friendly_name text UNIQUE,
    primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
    role_id bigint NOT NULL REFERENCES iam_role(id),
    role_grant text NOT NULL
  );