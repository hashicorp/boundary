begin;

  -- an iam_user can have 0 to many user_sessions
  -- an auth method can have 0 to many user_sessions
  -- a user session belongs to 1 and only 1 iam_user
  -- a user session belongs to 1 and only 1 auth methods
  create table user_session (
    public_id wt_public_id primary key,
    token text not null unique,
    iam_scope_id wt_public_id not null
      references iam_scope_organization (scope_id)
      on delete cascade
      on update cascade,
    iam_user_id wt_public_id not null unique -- read only
        references iam_user (public_id)
        on delete cascade
        on update cascade,
    -- TODO: Add an auth_method_id as a FK column that cascades.
    auth_method_id text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    last_access_time wt_timestamp,
    expiration_time wt_timestamp
  );


  create or replace function
    update_last_access_time_column()
    returns trigger
  as $$
  begin
    if row(new.last_access_time) is distinct from row(old.last_access_time) then
      new.last_access_time = now();
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
    immutable_iam_user_id()
    returns trigger
  as $$
  begin
    if new.iam_user_id is distinct from old.iam_user_id then
      raise exception 'iam_user_id cannot be set to %', new.iam_user_id;
      new.iam_user_id = old.iam_user_id;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    immutable_iam_user_id()
  is
    'function used in before update triggers to make iam_user_id column immutable';

  create or replace function
    immutable_auth_method_id()
    returns trigger
  as $$
  begin
    if new.auth_method_id is distinct from old.auth_method_id then
      raise exception 'auth_method_id cannot be set to %', new.auth_method_id;
      new.auth_method_id = old.auth_method_id;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    immutable_auth_method_id()
  is
    'function used in before update triggers to make auth_method_id column immutable';

  create or replace function
    immutable_iam_scope_id()
    returns trigger
  as $$
  begin
    if new.iam_scope_id is distinct from old.iam_scope_id then
      raise exception 'iam_scope_id cannot be set to %', new.iam_scope_id;
      new.iam_scope_id = old.iam_scope_id;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    immutable_iam_scope_id()
  is
    'function used in before update triggers to make iam_scope_id column immutable';

  create or replace function
    user_session_iam_user_scope_check()
    returns trigger
  as $$
  declare cnt int;
  begin
    select count(*) into cnt
    from iam_user
    where public_id = new.iam_user_id and
    scope_id = new.iam_scope_id;
    if cnt = 0 then
      raise exception 'session and user do not belong to the same organization';
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    user_session_iam_user_scope_check()
  is
    'function used in before insert triggers to check the iam user and the session are in the same scope.';

-- TODO: Create a similar function as above for the auth_method table when it exists.

  create trigger
    default_create_time_column
  before insert on user_session
    for each row execute procedure default_create_time();

  create trigger
    user_session_iam_user_scope_check
  before insert on user_session
    for each row execute procedure user_session_iam_user_scope_check();

  create trigger
    update_time_column
  before update on user_session
    for each row execute procedure update_time_column();

  create trigger
    update_last_access_time_column
  before update on user_session
    for each row execute procedure update_last_access_time_column();

  create trigger
    immutable_create_time
  before update on user_session
    for each row execute procedure immutable_create_time_func();

  create trigger
    immutable_iam_user_id
  before update on user_session
    for each row execute procedure immutable_iam_user_id();

  create trigger
    immutable_auth_method_id
  before update on user_session
    for each row execute procedure immutable_auth_method_id();

  create trigger
    immutable_iam_scope_id
  before update on user_session
    for each row execute procedure immutable_iam_scope_id();

  insert into oplog_ticket (name, version)
  values
    ('user_session', 1);

commit;
