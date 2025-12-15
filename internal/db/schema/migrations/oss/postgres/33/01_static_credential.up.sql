-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_static_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    constraint credential_store_fkey
      foreign key (scope_id, public_id)
      references credential_store (scope_id, public_id)
      on delete cascade
      on update cascade,
    constraint credential_static_store_scope_id_name_uq
      unique(scope_id, name)
  );
  comment on table credential_static_store is
    'credential_static_store is a table where each row is a resource that represents a static credential store. '
    'It is a credential_store subtype and an aggregate root.';

  create trigger update_version_column after update on credential_static_store
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_static_store
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_static_store
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_static_store
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time');

  create trigger insert_credential_store_subtype before insert on credential_static_store
    for each row execute procedure insert_credential_store_subtype();

  create trigger delete_credential_store_subtype after delete on credential_static_store
    for each row execute procedure delete_credential_store_subtype();

  create table credential_static_username_password_credential (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_static_store_fkey
        references credential_static_store (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,

    username text not null
      constraint username_must_not_be_empty
        check(length(trim(username)) > 0),
    password_encrypted bytea not null
      constraint password_encrypted_must_not_be_empty
        check(length(password_encrypted) > 0),
    password_hmac bytea not null
      constraint password_hmac_must_not_be_empty
        check(length(password_hmac) > 0),
    key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    constraint credential_static_fkey
      foreign key (store_id, public_id)
      references credential_static (store_id, public_id)
      on delete cascade
      on update cascade,

    constraint credential_static_username_password_credential_store_id_name_uq
      unique(store_id, name),

    -- The name of this constraint does not follow our naming conventions for
    -- unique constraints because it would be to long. The max length for
    -- identifiers in PostgreSQL is 63 characters.
    -- credential_static_username_password_credential_store_id_public_id_uq
    -- is 68 characters.
    --
    -- https://www.postgresql.org/docs/current/limits.html
    -- Constraint renamed in 69/01_rename_constraints.up.sql
    constraint credential_static_username_password_store_id_public_id_uq
      unique(store_id, public_id)
  );
  comment on table credential_static_username_password_credential is
    'credential_static_username_password_credential is a table where each row is a resource that represents a static username password credential. '
    'It is a credential_static subtype and an aggregate root.';

  create trigger update_version_column after update on credential_static_username_password_credential
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_static_username_password_credential
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_static_username_password_credential
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_static_username_password_credential
    for each row execute procedure immutable_columns('public_id', 'store_id','create_time');

  create trigger insert_credential_static_subtype before insert on credential_static_username_password_credential
    for each row execute procedure insert_credential_static_subtype();

  create trigger delete_credential_static_subtype after delete on credential_static_username_password_credential
    for each row execute procedure delete_credential_static_subtype();

  insert into oplog_ticket (name, version)
    values
      ('credential_static_store', 1),
      ('credential_static_username_password_credential', 1);

commit;
