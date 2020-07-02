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
    public_id wt_public_id not null primary key, 
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

CREATE TABLE iam_action_enm (
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




CREATE TABLE iam_role_grant (
    public_id wt_public_id not null primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    description text,
    role_id wt_public_id NOT NULL REFERENCES iam_role(public_id) ON DELETE CASCADE ON UPDATE CASCADE,
    "grant" text NOT NULL
  );

  COMMIT;
