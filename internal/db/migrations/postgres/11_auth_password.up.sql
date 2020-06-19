begin;

  create table auth_password_method (
    auth_method_id wt_public_id primary key
      references auth_method (auth_method_id)
      on delete cascade
      on update cascade,
    iam_scope_id wt_public_id not null -- read only
      references iam_scope(public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    min_user_name_length int not null default 5,
    min_password_length int not null default 8,
    unique(iam_scope_id, name)
  );

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
    insert_auth_method_subtype
  before update on auth_password_method
    for each row execute procedure insert_auth_method_subtype();

  create table auth_password_account (
    auth_account_id wt_public_id primary key
      references auth_account (auth_account_id)
      on delete cascade
      on update cascade,
    auth_method_id wt_public_id not null
      references auth_password_method (auth_method_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    user_name text not null
      check(length(trim(user_name)) > 0),
    unique(auth_method_id, name),
    unique(auth_method_id, user_name)
  );

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

  create trigger
    insert_auth_account_subtype
  before update on auth_password_account
    for each row execute procedure insert_auth_account_subtype();

  create table auth_password_credential (
    auth_password_credential_id wt_public_id primary key,
    auth_account_id wt_public_id not null unique
      references auth_password_account (auth_account_id)
      on delete cascade
      on update cascade
  );

  create or replace function
    insert_auth_password_credential_subtype()
    returns trigger
  as $$
  begin
    insert into auth_password_credential
      (auth_password_credential_id, auth_account_id)
    values
      (new.auth_password_credential_id, new.auth_account_id);
    return new;
  end;
  $$ language plpgsql;

  create table auth_password_conf (
    auth_password_conf_id wt_public_id primary key
  );

  create or replace function
    insert_auth_password_conf_subtype()
    returns trigger
  as $$
  begin
    insert into auth_password_conf (auth_password_conf_id)
    values
      (new.auth_password_conf_id);
    return new;
  end;
  $$ language plpgsql;

  create table auth_password_argon2_conf (
    auth_password_conf_id wt_public_id primary key
      references auth_password_conf (auth_password_conf_id)
      on delete cascade
      on update cascade,
    auth_method_id wt_public_id not null
      references auth_password_method (auth_method_id)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    iterations int not null
      check(iterations > 0),
    memory int not null
      check(memory > 0),
    threads int not null
      check(threads > 0),
    -- salt_length unit is bytes
    salt_length int not null
    -- minimum of 16 bytes (128 bits)
      check(salt_length >= 16),
    -- key_length unit is bytes
    key_length int not null
    -- minimum of 16 bytes (128 bits)
      check(key_length >= 16),
    unique(auth_method_id, iterations, memory, threads, salt_length, key_length)
  );

  create trigger
    immutable_create_time
  before
  update on auth_password_argon2_conf
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_password_argon2_conf
    for each row execute procedure default_create_time();

  create trigger
    insert_auth_password_conf_subtype
  before update on auth_password_argon2_conf
    for each row execute procedure insert_auth_password_conf_subtype();

  create table auth_password_argon2_cred (
    auth_password_credential_id wt_public_id primary key
      references auth_password_credential (auth_password_credential_id)
      on delete cascade
      on update cascade,
    auth_account_id wt_public_id not null unique
      references auth_password_account (auth_account_id)
      on delete cascade
      on update cascade,
    auth_password_conf_id wt_public_id not null
      references auth_password_argon2_conf (auth_password_conf_id)
      on delete restrict
      on update restrict,
    create_time wt_timestamp,
    update_time wt_timestamp,
    salt bytea not null, -- cannot be changed unless hashed_password is changed too
    hashed_password bytea not null
  );

  create trigger
    update_time_column
  before
  update on auth_password_argon2_cred
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on auth_password_argon2_cred
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_password_argon2_cred
    for each row execute procedure default_create_time();

  create trigger
    insert_auth_password_credential_subtype
  before update on auth_password_argon2_cred
    for each row execute procedure insert_auth_password_credential_subtype();

commit;
