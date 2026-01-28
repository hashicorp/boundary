-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- The base abstract table
create table auth_managed_group (
  public_id wt_public_id primary key,
  auth_method_id wt_public_id not null,
  -- Ensure that if the auth method is deleted (which will also happen if the
  -- scope is deleted) this is deleted too
  constraint auth_method_fkey
    foreign key (auth_method_id) -- fk1
      references auth_method(public_id)
      on delete cascade
      on update cascade,
  constraint auth_managed_group_auth_method_id_public_id_uq
    unique(auth_method_id, public_id)
);
comment on table auth_managed_group is
'auth_managed_group is the abstract base table for managed groups.';

-- Define the immutable fields of auth_managed_group
create trigger immutable_columns before update on auth_managed_group
  for each row execute procedure immutable_columns('public_id', 'auth_method_id');

-- Function to insert into the base table when values are inserted into a
-- concrete type table. This happens before inserts so the foreign keys in the
-- concrete type will be valid.
create or replace function insert_managed_group_subtype() returns trigger
as $$
begin

  insert into auth_managed_group
    (public_id, auth_method_id)
  values
    (new.public_id, new.auth_method_id);

  return new;

end;
$$ language plpgsql;

-- delete_managed_group_subtype() is an after delete trigger
-- function for subtypes of managed_group
create or replace function delete_managed_group_subtype() returns trigger
as $$
begin
  delete from auth_managed_group
  where public_id = old.public_id;
  return null; -- result is ignored since this is an after trigger
end;
$$ language plpgsql;

commit;
