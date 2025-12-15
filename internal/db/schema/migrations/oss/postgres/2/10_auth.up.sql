-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- By adding the name column to the base auth method type, the database can
-- ensure that auth method names are unique across all sub types.
alter table auth_method
  add column name wt_name;

alter table auth_method
  add constraint auth_method_scope_id_name_uq
    unique (scope_id, name);


-- the intent of this statement is to update the base type's name with the
-- existing password auth method names.
update auth_method 
set name = pw.name
from 
  auth_password_method pw
where 
  auth_method.public_id = pw.public_id and
  pw.name is not null;

-- insert_auth_method_subtype() is a replacement of the function definition in
-- migration 07_auth.up.sql  This new definition also inserts the sub type's name
-- into the base type. The name column must be on the base type, so the database
-- can ensure that auth method names are unique across all sub types.
-- Replaced in 81/09_auth_method_base_table_updates.up.sql
create or replace function insert_auth_method_subtype() returns trigger
as $$
begin
  insert into auth_method
    (public_id, scope_id, name)
  values
    (new.public_id, new.scope_id, new.name);
  return new;
end;
$$ language plpgsql;
comment on function insert_auth_method_subtype() is
  'insert_auth_method_subtype() inserts sub type name into the base type auth method table';

-- update_auth_method_subtype() is a new function intended to be used in "before
-- update" triggers for all auth method sub types.  It's purpose is to ensure
-- that the name column is syncronized between the sub and base auth method
-- types.  The name column must be on the base type, so the database can ensure
-- that auth method names are unique across all sub types.
create or replace function update_auth_method_subtype() returns trigger
as $$
begin
  update auth_method set name = new.name where public_id = new.public_id and new.name != name;
  return new;
end;
$$ language plpgsql;
comment on function update_auth_method_subtype() is
  'update_auth_method_subtype() will update base auth method type name column with new values from sub type';

create trigger update_auth_method_subtype before update on auth_oidc_method
  for each row execute procedure update_auth_method_subtype();

create trigger update_auth_method_subtype before update on auth_password_method
  for each row execute procedure update_auth_method_subtype();

-- delete_auth_method_subtype() is an after trigger function for subytypes of
-- auth_method
create or replace function delete_auth_method_subtype() returns trigger
as $$
begin
  delete from auth_method
  where public_id = old.public_id;
  return null; -- results are ignore since this is an after trigger.
end;
$$ language plpgsql;
comment on function delete_auth_method_subtype is
  'delete_auth_method_subtype() is an after trigger function for subytypes of auth_method';

create trigger delete_auth_method_subtype after delete on auth_oidc_method
  for each row execute procedure delete_auth_method_subtype();

create trigger delete_auth_method_subtype after delete on auth_password_method
  for each row execute procedure delete_auth_method_subtype();

commit;
