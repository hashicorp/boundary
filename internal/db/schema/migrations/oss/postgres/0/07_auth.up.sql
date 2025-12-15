-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

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
  │ public_id (pk) │          │ public_id         (pk)   │
  │ scope_id  (fk) │   ◀fk2   │ scope_id          (fk1)  │
  │                │┼○──────○┼│ auth_method_id    (fk1)  │
  │                │          │ iam_user_scope_id (fk2)  │
  └────────────────┘          │ iam_user_id       (fk2)  │
                              └──────────────────────────┘

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
    -- The auth_account can only be assigned to an iam_user in the same scope as
    -- the auth_method the auth_account belongs to. A separate column for
    -- iam_user's scope id is needed because using the scope_id column in the
    -- foreign key constraint causes an error when the iam_user is deleted but
    -- the auth_account still exists. This is a valid scenario since the
    -- lifetime of the auth_account is tied to the auth_method not the iam_user.
    iam_user_scope_id wt_scope_id,
      constraint user_and_auth_account_in_same_scope
      check(
        (iam_user_id is null and iam_user_scope_id is null)
        or
        (iam_user_id is not null and (iam_user_scope_id = scope_id))
      ),
    -- including scope_id in fk1 and fk2 ensures the scope_id of the owning
    -- auth_method and the scope_id of the owning iam_user are the same
    foreign key (scope_id, auth_method_id) -- fk1
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (iam_user_scope_id, iam_user_id) -- fk2
      references iam_user (scope_id, public_id)
      on delete set null
      on update cascade,
    unique(scope_id, auth_method_id, public_id)
  );

  create or replace function insert_auth_method_subtype() returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  create or replace function insert_auth_account_subtype() returns trigger
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

  -- update_iam_user_auth_account is a before update trigger on the auth_account
  -- table. If the new.iam_user_id column is different from the old.iam_user_id
  -- column, update_iam_user_auth_account retrieves the scope id of the iam user
  -- and sets new.iam_user_scope_id to that value. If the new.iam_user_id column
  -- is null and the old.iam_user_id column is not null,
  -- update_iam_user_auth_account sets the iam_user_scope_id to null.
  create or replace function update_iam_user_auth_account() returns trigger
  as $$
  begin
    if new.iam_user_id is distinct from old.iam_user_id then
      if new.iam_user_id is null then
        new.iam_user_scope_id = null;
      else
        select iam_user.scope_id into new.iam_user_scope_id
          from iam_user
         where iam_user.public_id = new.iam_user_id;
      end if;
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger update_iam_user_auth_account before update of iam_user_id on auth_account for each row
    execute procedure update_iam_user_auth_account();

commit;
