begin;

  create table auth_password_argon2_conf (
    public_id wt_public_id primary key
      references auth_password_conf (public_id)
      on delete cascade
      on update cascade,
    auth_password_method_id wt_public_id not null,
    create_time wt_timestamp,
    iterations int not null default 3
      check(iterations > 0),
    memory int not null default 65536
      check(memory > 0),
    threads int not null default 1
      check(threads > 0),
    -- salt_length unit is bytes
    salt_length int not null default 32
    -- minimum of 16 bytes (128 bits)
      check(salt_length >= 16),
    -- key_length unit is bytes
    key_length int not null default 32
    -- minimum of 16 bytes (128 bits)
      check(key_length >= 16),
    unique(auth_password_method_id, iterations, memory, threads, salt_length, key_length),
    unique (auth_password_method_id, public_id),
    foreign key (auth_password_method_id, public_id)
      references auth_password_conf (auth_password_method_id, public_id)
      on delete cascade
      on update cascade
      deferrable initially deferred
  );

  create or replace function
    read_only_auth_password_argon2_conf()
    returns trigger
  as $$
  begin
    raise exception 'auth_password_argon2_conf is read-only';
  end;
  $$ language plpgsql;

  create trigger
    read_only_auth_password_argon2_conf
  before
  update on auth_password_argon2_conf
    for each row execute procedure read_only_auth_password_argon2_conf();

  create trigger
    insert_auth_password_conf_subtype
  before insert on auth_password_argon2_conf
    for each row execute procedure insert_auth_password_conf_subtype();

  create table auth_password_argon2_cred (
    public_id wt_public_id primary key
      references auth_password_credential (public_id)
      on delete cascade
      on update cascade,
    auth_password_account_id wt_public_id not null,
    auth_password_conf_id wt_public_id not null,
    auth_password_method_id wt_public_id not null,
    create_time wt_timestamp,
    update_time wt_timestamp,
    salt bytea not null, -- cannot be changed unless hashed_password is changed too
    hashed_password bytea not null,
    foreign key (auth_password_method_id, auth_password_conf_id)
      references auth_password_argon2_conf (auth_password_method_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (auth_password_method_id, auth_password_conf_id, auth_password_account_id)
      references auth_password_credential (auth_password_method_id, auth_password_conf_id, auth_password_account_id)
      on delete cascade
      on update cascade
  );

  create trigger
    insert_auth_password_credential_subtype
  before insert on auth_password_argon2_cred
    for each row execute procedure insert_auth_password_credential_subtype();

  --
  -- triggers for time columns
  ---

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

  insert into oplog_ticket (name, version)
  values
    ('auth_password_argon2_conf', 1),
    ('auth_password_argon2_cred', 1);

commit;
