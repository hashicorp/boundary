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
-- we must wait until the iam_user table is defined, before we can add a fk constraint to iam_user
-- we cannot restrict NULL values for owner_id, because we need to create the scope before the user
CREATE TABLE if not exists iam_scope (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL,
  friendly_name text,
  type int NOT NULL,
  parent_id bigint REFERENCES iam_scope(id),
  owner_id bigint NOT NULL
);
CREATE TABLE if not exists iam_assignable_scope (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text not null,
  friendly_name text,
  primary_scope_id bigint NOT NULL REFERENCES iam_scope(id),
  iam_assignable_scope bigint NOT NULL REFERENCES iam_scope(id)
);
CREATE TABLE if not exists iam_user (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone NOT NULL default current_timestamp,
  update_time timestamp with time zone NOT NULL default current_timestamp,
  public_id text not null,
  friendly_name text,
  name text NOT NULL,
  primary_scope_id bigint REFERENCES iam_scope(id),
  owner_id bigint REFERENCES iam_user(id)
);
ALTER TABLE iam_scope
ADD
  CONSTRAINT iam_scope_owner_id_fk FOREIGN KEY (owner_id) REFERENCES iam_user(id) ON DELETE CASCADE ON UPDATE CASCADE;