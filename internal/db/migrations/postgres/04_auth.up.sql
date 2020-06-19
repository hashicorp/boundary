begin;

  -- base table for auth methods
  create table auth_method (
    auth_method_id wt_public_id primary key
  );


  -- base table for auth accounts
  create table auth_account (
    auth_account_id wt_public_id primary key
  );


  create or replace function
    insert_auth_method_subtype()
    returns trigger
  as $$
  begin
    insert into auth_method (auth_method_id)
    values
      (new.auth_method_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function
    insert_auth_account_subtype()
    returns trigger
  as $$
  begin
    insert into auth_account (auth_account_id)
    values
      (new.auth_account_id);
    return new;
  end;
  $$ language plpgsql;

commit;
