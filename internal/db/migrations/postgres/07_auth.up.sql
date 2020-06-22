begin;

  -- Design influenced by:
  -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
  --
  -- iam_scope ←─────  auth_method
  --    ↑                  ↑
  -- iam_user  ←─────  auth_account

  -- base table for auth methods
  create table auth_method (
    public_id wt_public_id primary key,
    scope_id wt_public_id not null
      references iam_scope(public_id)
      on delete cascade
      on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(scope_id, public_id)
  );


  -- base table for auth accounts
  create table auth_account (
    public_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    scope_id wt_public_id not null,
    iam_user_id wt_public_id,
    foreign key (scope_id, auth_method_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, iam_user_id)
      references iam_user (scope_id, public_id)
      on delete set null
      on update cascade,
    unique(scope_id, auth_method_id, public_id)
  );


  create or replace function
    insert_auth_method_subtype()
    returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function
    insert_auth_account_subtype()
    returns trigger
  as $$
  begin
    insert into auth_account
      (public_id, auth_method_id, scope_id)
    values
      (new.public_id, new.auth_method_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;


commit;
