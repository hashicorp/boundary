begin;

  -- an iam_user can have 0 to many auth_tokens
  -- an auth method can have 0 to many auth_tokens
  -- a user session belongs to 1 and only 1 iam_user
  -- a user session belongs to 1 and only 1 auth methods
  create table auth_token (
    public_id wt_public_id primary key,
    token text not null unique,
    scope_id wt_public_id not null,
    iam_user_id wt_public_id not null,
    auth_method_id wt_public_id not null,
    create_time wt_timestamp,
    update_time wt_timestamp,
    last_access_time wt_timestamp,
    expiration_time wt_timestamp,
    foreign key (scope_id, auth_method_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, iam_user_id)
      references iam_user (scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, public_id)
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
    immutable_scope_id()
    returns trigger
  as $$
  begin
    if new.scope_id is distinct from old.scope_id then
      raise exception 'scope_id cannot be set to %', new.scope_id;
      new.scope_id = old.scope_id;
    end if;
    return new;
  end;
  $$ language plpgsql;

  comment on function
    immutable_scope_id()
  is
    'function used in before update triggers to make scope_id column immutable';

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
    immutable_iam_user_id
  before update on auth_token
    for each row execute procedure immutable_iam_user_id();

  create trigger
    immutable_auth_method_id
  before update on auth_token
    for each row execute procedure immutable_auth_method_id();

  create trigger
    immutable_scope_id
  before update on auth_token
    for each row execute procedure immutable_scope_id();

  insert into oplog_ticket (name, version)
  values
    ('auth_token', 1);

commit;
