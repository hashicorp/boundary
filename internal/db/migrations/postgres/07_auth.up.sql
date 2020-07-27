begin;

/*

  ┌────────────────┐               ┌────────────────┐
  │   iam_scope    │               │  auth_method   │
  ├────────────────┤               ├────────────────┤
  │ public_id (pk) │              ╱│ public_id (pk) │
  │                │┼┼───────────○─│ scope_id  (fk) │
  │                │              ╲│                │
  └────────────────┘               └────────────────┘
           ┼                                ┼
           ┼                                ┼
           │                                │
           │                                │ ▲fk1
           │                                │
           ○                                ○
          ╱│╲                              ╱│╲
  ┌────────────────┐          ┌──────────────────────────┐
  │    iam_user    │          │       auth_account       │
  ├────────────────┤          ├──────────────────────────┤
  │ public_id (pk) │          │ public_id      (pk)      │
  │ scope_id  (fk) │   ◀fk2   │ scope_id       (fk1,fk2) │
  │                │┼○──────○┼│ auth_method_id (fk1)     │
  │                │          │ iam_user_id    (fk2)     │
  └────────────────┘          └──────────────────────────┘

  An iam_scope can have 0 to many iam_users.
  An iam_scope can have 0 to many auth_methods.

  An iam_user belongs to 1 iam_scope.
  An auth_method belongs to 1 iam_scope.

  An iam_user can have 0 or 1 auth_account.
  An auth_account belongs to 0 or 1 iam_user.

  An auth_method can have 0 to many auth_accounts.
  An auth_account belongs to 1 auth_account.

  An auth_account can only be associated with an iam_user in the same scope of
  the auth_account's auth_method. Including scope_id in fk1 and fk2 ensures this
  restriction is not violated.

  Design influenced by:
  https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972

*/

  -- base table for auth methods
  create table auth_method (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
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
    scope_id wt_scope_id not null,
    iam_user_id wt_public_id,
    -- including scope_id in fk1 and fk2 ensures the scope_id of the owning
    -- auth_method and the scope_id of the owning iam_user are the same
    foreign key (scope_id, auth_method_id) -- fk1
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, iam_user_id) -- fk2
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

    select auth_method.scope_id
      into new.scope_id
    from auth_method
    where auth_method.public_id = new.auth_method_id;

    insert into auth_account
      (public_id, auth_method_id, scope_id)
    values
      (new.public_id, new.auth_method_id, new.scope_id);

    return new;

  end;
  $$ language plpgsql;

commit;
