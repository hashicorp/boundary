-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table auth_password_argon2_conf (
    private_id wt_private_id primary key
      references auth_password_conf (private_id)
      on delete cascade
      on update cascade,
    password_method_id wt_public_id not null,
    create_time wt_timestamp,
    iterations int not null default 3
      constraint iterations_must_be_greater_than_0
      check(iterations > 0),
    memory int not null default 65536
      constraint memory_must_be_greater_than_0
      check(memory > 0),
    threads int not null default 1
      constraint threads_must_be_greater_than_0
      check(threads > 0),
    -- salt_length unit is bytes
    salt_length int not null default 32
    -- minimum of 16 bytes (128 bits)
      constraint salt_must_be_at_least_16_bytes
      check(salt_length >= 16),
    -- key_length unit is bytes
    key_length int not null default 32
    -- minimum of 16 bytes (128 bits)
      constraint key_length_must_be_at_least_16_bytes
      check(key_length >= 16),
    unique(password_method_id, iterations, memory, threads, salt_length, key_length),
    unique (password_method_id, private_id),
    foreign key (password_method_id, private_id)
      references auth_password_conf (password_method_id, private_id)
      on delete cascade
      on update cascade
      deferrable initially deferred
  );

  create or replace function read_only_auth_password_argon2_conf() returns trigger
  as $$
  begin
    raise exception 'auth_password_argon2_conf is read-only';
  end;
  $$ language plpgsql;

  create trigger read_only_auth_password_argon2_conf before update on auth_password_argon2_conf
    for each row execute procedure read_only_auth_password_argon2_conf();

  create trigger insert_auth_password_conf_subtype before insert on auth_password_argon2_conf
    for each row execute procedure insert_auth_password_conf_subtype();

  create table auth_password_argon2_cred (
    private_id wt_private_id primary key
      references auth_password_credential (private_id)
      on delete cascade
      on update cascade,
    password_account_id wt_public_id not null,
    password_conf_id wt_private_id,
    -- NOTE(mgaffney): The password_method_id type is not wt_public_id because
    -- the domain check is executed before the insert trigger which retrieves
    -- the password_method_id causing an insert to fail.
    password_method_id text not null,
    create_time wt_timestamp,
    update_time wt_timestamp,
    salt bytea not null -- cannot be changed unless derived_key is changed too
      constraint salt_must_not_be_empty
      check(length(salt) > 0),
    derived_key bytea not null
      constraint derived_key_must_not_be_empty
      check(length(derived_key) > 0),
    -- TODO: Make key_id a foreign key once we have DEKs
    key_id text not null
      constraint key_id_must_not_be_empty
      check(length(trim(key_id)) > 0),
    foreign key (password_method_id, password_conf_id)
      references auth_password_argon2_conf (password_method_id, private_id)
      on delete cascade
      on update cascade,
    foreign key (password_method_id, password_conf_id, password_account_id)
      references auth_password_credential (password_method_id, password_conf_id, password_account_id)
      on delete cascade
      on update cascade
      deferrable initially deferred
  );

  create trigger insert_auth_password_credential_subtype before insert on auth_password_argon2_cred
    for each row execute procedure insert_auth_password_credential_subtype();

  create trigger update_auth_password_credential_subtype after update on auth_password_argon2_cred
    for each row execute procedure update_auth_password_credential_subtype();

  create trigger delete_auth_password_credential_subtype after delete on auth_password_argon2_cred
    for each row execute procedure delete_auth_password_credential_subtype();

  --
  -- triggers for time columns
  --

  create trigger immutable_columns before update on auth_password_argon2_conf
    for each row execute procedure immutable_columns('create_time');

  create trigger default_create_time_column before insert on auth_password_argon2_conf
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on auth_password_argon2_cred
    for each row execute procedure update_time_column();

  create trigger immutable_columns before update on auth_password_argon2_cred
    for each row execute procedure immutable_columns('create_time');

  create trigger default_create_time_column before insert on auth_password_argon2_cred
    for each row execute procedure default_create_time();

  -- The tickets for oplog are the subtypes not the base types because no updates
  -- are done to any values in the base types.
  insert into oplog_ticket
    (name, version)
  values
    ('auth_password_argon2_conf', 1),
    ('auth_password_argon2_cred', 1);

commit;
