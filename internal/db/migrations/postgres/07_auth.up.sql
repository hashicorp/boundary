begin;

  -- Design influenced by:
  -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
  --
  -- iam_scope ←─────  auth_method
  --    ↑                  ↑
  -- iam_user  ←─────  auth_account

  -- base table for auth methods
  create table auth_method (
    auth_method_id wt_public_id primary key,
    iam_scope_id wt_public_id not null
      references iam_scope(public_id)
      on delete cascade
      on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(iam_scope_id, auth_method_id)
  );


  -- base table for auth accounts
  create table auth_account (
    auth_account_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    iam_scope_id wt_public_id not null,
    iam_user_id wt_public_id,
    foreign key (iam_scope_id, auth_method_id)
      references auth_method (iam_scope_id, auth_method_id)
      on delete cascade
      on update cascade,
    foreign key (iam_scope_id, iam_user_id)
      references iam_user (scope_id, public_id)
      on delete set null
      on update cascade
  );


  create or replace function
    insert_auth_method_subtype()
    returns trigger
  as $$
  begin
    insert into auth_method
      (auth_method_id, iam_scope_id)
    values
      (new.auth_method_id, new.iam_scope_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function
    insert_auth_account_subtype()
    returns trigger
  as $$
  begin
    insert into auth_account
      (auth_account_id, auth_method_id, iam_scope_id)
    values
      (new.auth_account_id, new.auth_method_id, new.iam_scope_id);
    return new;
  end;
  $$ language plpgsql;


alter table iam_user_account 
   add constraint fk_auth_method
   foreign key (auth_method_id) 
   references auth_method(auth_method_id);

alter table iam_user_account 
   add constraint fk_auth_account
   foreign key (auth_account_id) 
   references auth_account(auth_account_id);

commit;
