-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*

       ┌────────────────┐                 ┌──────────────────────┐             ┌────────────────────────────┐
       │  auth_method   │                 │ auth_password_method │             │     auth_password_conf     │
       ├────────────────┤                 ├──────────────────────┤             ├────────────────────────────┤
       │ public_id (pk) │                 │ public_id (pk,fk)    │            ╱│ private_id         (pk,fk) │
       │ scope_id  (fk) │┼┼─────────────○┼│ scope_id  (fk)       │┼┼─────────○─│ password_method_id (fk)    │
       │                │                 │ ...                  │            ╲│                            │
       └────────────────┘                 └──────────────────────┘             └────────────────────────────┘
                ┼                                     ┼                                       ┼
                ┼                                     ┼                                       ┼
                │                                     │                                       │
                │ ▲fk1                                │ ▲fk1                                  │ ▲fk1
                │                                     │                                       │
                ○                                     ○                                       ○
               ╱│╲                                   ╱│╲                                     ╱│╲
  ┌──────────────────────────┐          ┌──────────────────────────┐          ┌───────────────────────────────┐
  │       auth_account       │          │  auth_password_account   │          │   auth_password_credential    │
  ├──────────────────────────┤          ├──────────────────────────┤          ├───────────────────────────────┤
  │ public_id         (pk)   │          │ public_id      (pk,fk2)  │          │ private_id          (pk)      │
  │ scope_id          (fk1)  │   ◀fk2   │ scope_id       (fk1,fk2) │   ◀fk2   │ password_method_id  (fk1,fk2) │
  │ auth_method_id    (fk1)  │┼┼──────○┼│ auth_method_id (fk1,fk2) │┼┼──────○┼│ password_conf_id    (fk1)     │
  │ iam_user_scope_id (fk2)  │          │ ...                      │          │ password_account_id (fk2)     │
  │ iam_user_id       (fk2)  │          └──────────────────────────┘          └───────────────────────────────┘
  └──────────────────────────┘

  An auth_method is a base type. An auth_password_method is an auth_method
  subtype. For every row in auth_password_method there is one row in auth_method
  with the same public_id and scope_id.

  Similarly, an auth_account is a base type. An auth_password_account is an
  auth_account subtype. For every row in auth_password_account there is one row
  in auth_account with the same public_id, scope_id, and auth_method_id.

  Both auth_password_conf and auth_password_credential are base types. Each
  password key derivation function will require a auth_password_conf and
  auth_password_credential table.

  An auth_method can have 0 or 1 auth_password_method.
  An auth_account can have 0 or 1 auth_password_account.

  An auth_password_method belongs to 1 auth_method.
  An auth_password_method can have 0 to many auth_password_accounts.
  An auth_password_method can have 0 to many auth_password_confs.

  An auth_password_account belongs to 1 auth_account.
  An auth_password_account belongs to 1 auth_password_method.
  An auth_password_account can have 0 or 1 auth_password_credential.

  An auth_password_conf belongs to 1 auth_password_method.
  An auth_password_conf can have 0 to many auth_password_credentials.

  An auth_password_credential belongs to 1 auth_password_account.
  An auth_password_credential belongs to 1 auth_password_conf.

*/

  create table auth_password_method (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null,
    password_conf_id wt_private_id, -- FK to auth_password_conf added below
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    min_login_name_length int not null default 3,
    min_password_length int not null default 8,
    version wt_version,
    foreign key (scope_id, public_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name),
    unique(scope_id, public_id)
  );

  create trigger update_version_column after update on auth_password_method
    for each row execute procedure update_version_column();

  create trigger insert_auth_method_subtype before insert on auth_password_method
    for each row execute procedure insert_auth_method_subtype();

  create table auth_password_account (
    public_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    -- NOTE(mgaffney): The scope_id type is not wt_scope_id because the domain
    -- check is executed before the insert trigger which retrieves the scope_id
    -- causing an insert to fail.
    scope_id text not null,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    login_name text not null
      constraint login_name_must_be_lowercase
        check(lower(trim(login_name)) = login_name)
      constraint login_name_must_not_be_empty
        check(length(trim(login_name)) > 0),
    version wt_version,
    foreign key (scope_id, auth_method_id)
      references auth_password_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, auth_method_id, public_id)
      references auth_account (scope_id, auth_method_id, public_id)
      on delete cascade
      on update cascade,
    unique(auth_method_id, name),
    unique(auth_method_id, login_name),
    unique(auth_method_id, public_id)
  );

  create trigger update_version_column after update on auth_password_account
    for each row execute procedure update_version_column();

  create trigger insert_auth_account_subtype before insert on auth_password_account
    for each row execute procedure insert_auth_account_subtype();

  create table auth_password_conf (
    private_id wt_private_id primary key,
    password_method_id wt_public_id not null
      references auth_password_method (public_id)
      on delete cascade
      on update cascade
      deferrable initially deferred,
    unique(password_method_id, private_id)
  );

  alter table auth_password_method
    add constraint current_conf_fkey
    foreign key (public_id, password_conf_id)
    references auth_password_conf (password_method_id, private_id)
    on delete cascade
    on update cascade
    deferrable initially deferred;

  -- insert_auth_password_conf_subtype() is a trigger function for subtypes of
  -- auth_password_conf
  create or replace function insert_auth_password_conf_subtype() returns trigger
  as $$
  begin
    insert into auth_password_conf
      (private_id, password_method_id)
    values
      (new.private_id, new.password_method_id);
    return new;
  end;
  $$ language plpgsql;

  create table auth_password_credential (
    private_id wt_private_id primary key,
    password_account_id wt_public_id not null unique,
    password_conf_id wt_private_id,
    password_method_id wt_public_id not null,
    foreign key (password_method_id, password_conf_id)
      references auth_password_conf (password_method_id, private_id)
      on delete cascade
      on update cascade,
    foreign key (password_method_id, password_account_id)
      references auth_password_account (auth_method_id, public_id)
      on delete cascade
      on update cascade,
    unique(password_method_id, password_conf_id, password_account_id)
  );

  -- insert_auth_password_credential_subtype() is a trigger function for
  -- subtypes of auth_password_credential
  create or replace function insert_auth_password_credential_subtype() returns trigger
  as $$
  begin

    select auth_password_account.auth_method_id
      into new.password_method_id
    from auth_password_account
    where auth_password_account.public_id = new.password_account_id;

    insert into auth_password_credential
      (private_id, password_account_id, password_conf_id, password_method_id)
    values
      (new.private_id, new.password_account_id, new.password_conf_id, new.password_method_id);
    return new;
  end;
  $$ language plpgsql;

  -- update_auth_password_credential_subtype() is an after update trigger
  -- function for subtypes of auth_password_credential
  create or replace function update_auth_password_credential_subtype() returns trigger
  as $$
  begin
    /*
      The configuration id of a credential is updated when a credential is
      rehashed during authentication.
    */
    if new.password_conf_id is distinct from old.password_conf_id then
      update auth_password_credential
         set password_conf_id = new.password_conf_id
       where private_id = new.private_id;
    end if;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- delete_auth_password_credential_subtype() is an after delete trigger
  -- function for subtypes of auth_password_credential
  create or replace function delete_auth_password_credential_subtype() returns trigger
  as $$
  begin
    delete
      from auth_password_credential
     where private_id = old.private_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  --
  -- triggers for time columns
  --

  create trigger update_time_column before update on auth_password_method
    for each row execute procedure update_time_column();

  create trigger immutable_columns before update on auth_password_method
    for each row execute procedure immutable_columns('create_time');

  create trigger default_create_time_column before insert on auth_password_method
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on auth_password_account
    for each row execute procedure update_time_column();

  create trigger immutable_columns before update on auth_password_account
    for each row execute procedure immutable_columns('create_time');

  create trigger default_create_time_column before insert on auth_password_account
    for each row execute procedure default_create_time();

  -- The tickets for oplog are the subtypes not the base types because no updates
  -- are done to any values in the base types.
  insert into oplog_ticket
    (name, version)
  values
    ('auth_password_method', 1),
    ('auth_password_account', 1),
    ('auth_password_credential', 1);

commit;
