BEGIN;

CREATE TABLE if not exists iam_user (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    external_name text NOT NULL,
    primary_scope_id text NOT NULL REFERENCES iam_scope_organization(scope_id),
    disabled BOOLEAN NOT NULL default FALSE
  );


CREATE TABLE if not exists iam_auth_method (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    primary_scope_id text NOT NULL REFERENCES iam_scope_organization(scope_id) ON DELETE CASCADE ON UPDATE CASCADE,
    disabled BOOLEAN NOT NULL default FALSE,
    type text NOT NULL
  );


CREATE TABLE if not exists iam_role (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    description text,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    disabled BOOLEAN NOT NULL default FALSE
  );

CREATE TABLE if not exists iam_group_member_type_enm (
    string text NOT NULL primary key CHECK(string IN ('unknown', 'user'))
  );
INSERT INTO iam_group_member_type_enm (string)
values
  ('unknown'),
  ('user');


CREATE TABLE if not exists iam_group (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    description text,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    disabled BOOLEAN NOT NULL default FALSE
  );


CREATE TABLE if not exists iam_group_member_user (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id),
    group_id text NOT NULL REFERENCES iam_group(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    member_id text NOT NULL REFERENCES iam_user(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    type text NOT NULL REFERENCES iam_group_member_type_enm(string) check(type = 'user')
  );


CREATE VIEW iam_group_member AS
SELECT
  *
FROM iam_group_member_user;


CREATE TABLE if not exists iam_auth_method_type_enm (
    string text NOT NULL primary key CHECK(string IN ('unknown', 'userpass', 'oidc'))
  );
INSERT INTO iam_auth_method_type_enm (string)
values
  ('unknown'),
  ('userpass'),
  ('oidc');
ALTER TABLE iam_auth_method
ADD
  FOREIGN KEY (type) REFERENCES iam_auth_method_type_enm(string);

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
  ('unknown'),
  ('list'),
  ('create'),
  ('update'),
  ('edit'),
  ('delete'),
  ('authen');


CREATE TABLE if not exists iam_role_type_enm (
    string text NOT NULL primary key CHECK(
      string IN (
        'unknown',
        'user',
        'group'
      )
    )
  );
INSERT INTO iam_role_type_enm (string)
values
  ('unknown'),
  ('user'),
  ('group');


CREATE TABLE if not exists iam_role_user (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    role_id text NOT NULL REFERENCES iam_role(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    principal_id text NOT NULL REFERENCES iam_user(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    type text NOT NULL REFERENCES iam_role_type_enm(string) CHECK(type = 'user')
  );


CREATE TABLE if not exists iam_role_group (
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    role_id text NOT NULL REFERENCES iam_role(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    principal_id text NOT NULL REFERENCES iam_group(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    type text NOT NULL REFERENCES iam_role_type_enm(string) CHECK(type = 'group')
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
    public_id text not null primary key,
    create_time timestamp with time zone NOT NULL default current_timestamp,
    update_time timestamp with time zone NOT NULL default current_timestamp,
    name text UNIQUE,
    primary_scope_id text NOT NULL REFERENCES iam_scope(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    role_id text NOT NULL REFERENCES iam_role(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    "grant" text NOT NULL,
    description text
  );

  COMMIT;