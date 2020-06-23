begin;

  -- iam_scope ←─────  auth_method  ←─────  auth_password_method
  --    ↑                  ↑                        ↑
  -- iam_user  ←─────  auth_account ←─────  auth_password_account

  create table auth_password_method (
    public_id wt_public_id primary key
      references auth_method (public_id)
      on delete cascade
      on update cascade,
    scope_id wt_public_id not null,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    min_user_name_length int not null default 5,
    min_password_length int not null default 8,
    foreign key (scope_id, public_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name),
    unique(scope_id, public_id)
  );

  create trigger
    insert_auth_method_subtype
  before insert on auth_password_method
    for each row execute procedure insert_auth_method_subtype();

  create table auth_password_account (
    public_id wt_public_id primary key
      references auth_account (public_id)
      on delete cascade
      on update cascade,
    auth_method_id wt_public_id not null,
    -- NOTE(mgaffney): The scope_id type is not wt_public_id because the domain
    -- check is executed before the insert trigger which retrieves the scope_id
    -- causing an insert to fail.
    scope_id text not null,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    user_name text not null
      check(length(trim(user_name)) > 0),
    foreign key (scope_id, auth_method_id)
      references auth_password_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, auth_method_id, public_id)
      references auth_account (scope_id, auth_method_id, public_id)
      on delete cascade
      on update cascade,
    unique(auth_method_id, name),
    unique(auth_method_id, user_name),
    unique(auth_method_id, public_id)
  );

  create trigger
    insert_auth_account_subtype
  before insert on auth_password_account
    for each row execute procedure insert_auth_account_subtype();

  create table auth_password_conf (
    public_id wt_public_id primary key,
    auth_password_method_id wt_public_id not null
      references auth_password_method (public_id)
      on delete cascade
      on update cascade,
    unique(auth_password_method_id, public_id)
  );

  create or replace function
    insert_auth_password_conf_subtype()
    returns trigger
  as $$
  begin
    insert into auth_password_conf
      (public_id, auth_password_method_id)
    values
      (new.public_id, new.auth_password_method_id);
    return new;
  end;
  $$ language plpgsql;

  create table auth_password_credential (
    public_id wt_public_id primary key,
    auth_password_account_id wt_public_id not null unique,
    auth_password_conf_id wt_public_id not null,
    auth_password_method_id wt_public_id not null,
    foreign key (auth_password_method_id, auth_password_conf_id)
      references auth_password_conf (auth_password_method_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (auth_password_method_id, auth_password_account_id)
      references auth_password_account (auth_method_id, public_id)
      on delete cascade
      on update cascade,
    unique(auth_password_method_id, auth_password_conf_id, auth_password_account_id)
  );

  create or replace function
    insert_auth_password_credential_subtype()
    returns trigger
  as $$
  begin
    insert into auth_password_credential
      (public_id, auth_password_account_id, auth_password_conf_id, auth_password_method_id)
    values
      (new.public_id, new.auth_password_account_id, new.auth_password_conf_id, new.auth_password_method_id);
    return new;
  end;
  $$ language plpgsql;

  --
  -- triggers for time columns
  ---

  create trigger
    update_time_column
  before
  update on auth_password_method
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on auth_password_method
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_password_method
    for each row execute procedure default_create_time();

  create trigger
    update_time_column
  before
  update on auth_password_account
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on auth_password_account
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_password_account
    for each row execute procedure default_create_time();

  insert into oplog_ticket (name, version)
  values
    ('auth_password_method', 1),
    ('auth_password_account', 1);

commit;
