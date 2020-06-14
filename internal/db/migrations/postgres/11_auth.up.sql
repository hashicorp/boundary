begin;

  -- an iam_user can have 0 to 1 auth_method
  -- an auth_method belongs to 1 and only 1 iam_user
  create table auth_method (
    auth_method_id wt_private_id primary key,
    iam_user_id wt_public_id not null unique -- read only
      references iam_user (public_id)
      on delete cascade
      on update cascade,
    create_time wt_timestamp
  );

  create trigger
    immutable_create_time
  before
  update on auth_method
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_method
    for each row execute procedure default_create_time();

  -- auth_usrpass is a auth_method
  -- a user_name is unique within a scope
  create table auth_usrpass (
    auth_method_id wt_private_id primary key
      references auth_method (auth_method_id)
      on delete cascade
      on update cascade,
    -- NOTE: there is no constraint to enforce the user is in this scope
    -- TODO(mgaffney) 06/2020: add insert trigger to check user is in scope
    iam_scope_id wt_public_id not null -- read only
      references iam_scope(public_id)
      on delete cascade
      on update cascade,
    user_name text not null
      -- TODO(mgaffney) 06/2020:
      -- check all lowercase
      -- check no spaces
      check(
        length(trim(user_name)) > 5
      ),
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(iam_scope_id, user_name)
  );

  create trigger
    update_time_column
  before
  update on auth_usrpass
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on auth_usrpass
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_usrpass
    for each row execute procedure default_create_time();

  -- TODO(mgaffney) 06/2020: insert and delete only, no updates
  create table auth_usrpass_argon2_conf (
    id bigint generated always as identity primary key,
    iam_scope_id wt_public_id not null
      references iam_scope(public_id)
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
    unique(iam_scope_id, iterations, memory, threads, salt_length, key_length)
  );

  create trigger
    immutable_create_time
  before
  update on auth_usrpass_argon2_conf
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_usrpass_argon2_conf
    for each row execute procedure default_create_time();

  -- auth_usrpass_argon2 is a auth_usrpass
  create table auth_usrpass_argon2 (
    auth_method_id wt_private_id primary key
      references auth_usrpass (auth_method_id)
      on delete cascade
      on update cascade,
    argon2_conf_id bigint not null -- cannot be changed unless hashed_password is changed too
      references auth_usrpass_argon2_conf (id)
      on delete restrict
      on update restrict,
    create_time wt_timestamp,
    update_time wt_timestamp,
    -- password_change_time is a timestamp of when the password was changed.
    -- The hashed_password field will change if the same password is hashed
    -- using different argon2 conf parameters. Therefore, only the domain layer
    -- can know when to set this value.
    password_change_time wt_timestamp,
    salt bytea not null, -- cannot be changed unless hashed_password is changed too
    hashed_password bytea not null

    -- TODO(mgaffney) 06/2020: Salt and hashed_password will be encrypted with
    -- the database DEK. Add foreign key to database DEK.

  );

  create trigger
    update_time_column
  before
  update on auth_usrpass_argon2
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on auth_usrpass_argon2
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on auth_usrpass_argon2
    for each row execute procedure default_create_time();

  /*
  TODO(mgaffney) 06/2020: auth_usrpass_argon2_conf needs a trigger to prevent
  updates. The output from the argon2 hash function is different if any of the
  input parameters, including the config parameters, have changed.
  */

commit;
