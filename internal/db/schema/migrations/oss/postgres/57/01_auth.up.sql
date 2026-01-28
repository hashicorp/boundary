-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- This deletes the base type if the concrete types exist anymore.
delete from auth_account
where public_id not in
      (select public_id
       from auth_oidc_account)
and public_id not in
    (select public_id
     from auth_password_account);

-- delete_auth_account_subtype() is an after trigger function for subytypes of
-- auth_account.
-- this function is similar to the delete_auth_method_subtype account created
-- in 2/10_auth.up.sql
create function delete_auth_account_subtype() returns trigger
as $$
begin
    delete from auth_account
    where public_id = old.public_id;
    return null; -- results are ignore since this is an after trigger.
end;
$$ language plpgsql;
comment on function delete_auth_account_subtype is
  'delete_auth_account_subtype() is an after trigger function for subytypes of auth_account';

create trigger delete_auth_account_subtype after delete on auth_oidc_account
    for each row execute procedure delete_auth_account_subtype();

create trigger delete_auth_account_subtype after delete on auth_password_account
    for each row execute procedure delete_auth_account_subtype();

commit;