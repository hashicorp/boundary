begin;

  -- an auth token belongs to 1 and only 1 auth account
  -- an auth account can have 0 to many auth tokens
  create table auth_token (
    public_id wt_public_id primary key,
    token bytea not null unique,
    auth_account_id wt_public_id not null
        references auth_account(public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    -- This column is not updated every time this auth token is accessed.
    -- It is updated after X minutes from the last time it was updated on
    -- a per row basis.
    approximate_last_access_time wt_timestamp,
    expiration_time wt_timestamp
  );

  create view auth_token_view as
  select at.*,
         aa.scope_id,
         aa.iam_user_id,
         aa.auth_method_id
  from auth_token as at
      INNER JOIN
      auth_account as aa ON at.auth_account_id = aa.public_id;

  create or replace function
    update_last_access_time_column()
    returns trigger
  as $$
  begin
    if new.approximate_last_access_time is null then
      new.approximate_last_access_time = now();
      return new;
    else
      return old;
    end if;
  end;
  $$ language plpgsql;

  comment on function
    update_last_access_time_column()
  is
    'function used in before update triggers to properly set last_access_time columns';

  create or replace function
    immutable_auth_token_columns()
    returns trigger
  as $$
  begin
    if new.auth_account_id is distinct from old.auth_account_id then
      raise exception 'auth_account_id cannot be set to %', new.auth_account_id;
    end if;
    if new.token is distinct from old.token then
        raise exception 'token cannot be set to %', new.token;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
      immutable_auth_token_columns()
  is
    'function used in before update triggers to make specific columns immutable';

  create trigger
    default_create_time_column
  before insert on auth_token
    for each row execute procedure default_create_time();

  create trigger
    update_time_column
  before update on auth_token
    for each row execute procedure update_time_column();

  create trigger
    update_last_access_time_column
  before update on auth_token
    for each row execute procedure update_last_access_time_column();

  create trigger
    immutable_create_time
  before update on auth_token
    for each row execute procedure immutable_create_time_func();

  create trigger
    immutable_auth_token_columns
  before update on auth_token
    for each row execute procedure immutable_auth_token_columns();

commit;
