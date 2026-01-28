-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- an auth token belongs to 1 and only 1 auth account
  -- an auth account can have 0 to many auth tokens
  create table auth_token (
    public_id wt_public_id primary key,
    token bytea not null unique,
    -- TODO: Make key_id a foreign key once we have DEKs
    key_id text not null
      constraint key_id_must_not_be_empty
      check(length(trim(key_id)) > 0),
    auth_account_id wt_public_id not null
      references auth_account(public_id)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    -- This column is not updated every time this auth token is accessed.
    -- It is updated after X minutes from the last time it was updated on
    -- a per row basis.
    approximate_last_access_time wt_timestamp
      constraint last_access_time_must_not_be_after_expiration_time
      check(
        approximate_last_access_time <= expiration_time
      ),
    expiration_time wt_timestamp
      constraint create_time_must_not_be_after_expiration_time
      check(
        create_time <= expiration_time
      )
  );

  create view auth_token_account as
        select at.public_id,
               at.token,
               at.auth_account_id,
               at.create_time,
               at.update_time,
               at.approximate_last_access_time,
               at.expiration_time,
               aa.scope_id,
               aa.iam_user_id,
               aa.auth_method_id
          from auth_token as at
    inner join auth_account as aa
            on at.auth_account_id = aa.public_id;

  create or replace function update_last_access_time() returns trigger
  as $$
  begin
    if new.approximate_last_access_time is distinct from old.approximate_last_access_time then
      new.approximate_last_access_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_last_access_time() is
    'function used in before update triggers to properly set last_access_time columns';

  -- this trigger is deleted in 56/05_mutable_ciphertext_columns.up.sql
  create or replace function immutable_auth_token_columns() returns trigger
  as $$
  begin
    if new.auth_account_id is distinct from old.auth_account_id then
      raise exception 'auth_account_id is read-only';
    end if;
    if new.token is distinct from old.token then
      raise exception 'token is read-only';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function immutable_auth_token_columns() is
    'function used in before update triggers to make specific columns immutable';

  -- This allows the expiration to be calculated on the server side and still hold the constraint that
  -- the expiration time cant be before the creation time of the auth token.
  create or replace function expire_time_not_older_than_token() returns trigger
  as $$
  begin
    if new.expiration_time < new.create_time then
      new.expiration_time = new.create_time;
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function expire_time_not_older_than_token() is
    'function used in before insert triggers to ensure expiration time is not older than create time';

  create trigger default_create_time_column before insert on auth_token
    for each row execute procedure default_create_time();

  create trigger expire_time_not_older_than_token before insert on auth_token
    for each row execute procedure expire_time_not_older_than_token();

  create trigger update_time_column before update on auth_token
    for each row execute procedure update_time_column();

  create trigger update_last_access_time before update on auth_token
    for each row execute procedure update_last_access_time();

  create trigger immutable_auth_token_columns before update on auth_token
    for each row execute procedure immutable_auth_token_columns();

  create trigger immutable_columns before update on auth_token
    for each row execute procedure immutable_columns('public_id', 'auth_account_id', 'create_time');

commit;
