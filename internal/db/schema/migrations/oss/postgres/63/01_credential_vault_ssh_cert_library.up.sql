-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- drop constraint so we can add ssh_certificate
  alter table credential_type_enm
    drop constraint only_predefined_credential_types_allowed;

  -- Add new constraint that only allows known types
  -- This replaces the constraint defined in 39/01_static_ssh_private_key_creds_up
  -- This constraint is replaced in 98/01_credential_static_username_password_domain_credential.up.sql
  alter table credential_type_enm
    add constraint only_predefined_credential_types_allowed
      check (
        name in (
          'unspecified',
          'username_password',
          'ssh_private_key',
          'ssh_certificate'
        )
      );

  insert into credential_type_enm (name)
   values ('ssh_certificate');

  create table credential_vault_ssh_cert_key_type_enm (
    name text primary key
      constraint only_predefined_key_types_allowed
      check (
        name in (
          'ed25519',
          'ecdsa',
          'rsa'
        )
      )
  );
  comment on table credential_vault_ssh_cert_key_type_enm is
    'credential_vault_ssh_cert_key_type_enm is an enumeration table for the ssh key type. ';

  insert into credential_vault_ssh_cert_key_type_enm (name)
  values
    ('ed25519'),
    ('ecdsa'),
    ('rsa');

  create table credential_vault_ssh_cert_key_bits_enm (
    bits int primary key
      constraint only_predefined_key_bits_allowed
      check (
        bits in (
          0,
          2048,
          3072,
          4096,
          256,
          384,
          521
        )
      )
  );
  comment on table credential_vault_ssh_cert_key_bits_enm is
    'credential_vault_ssh_cert_key_bits_enm is an enumeration table for the ssh key bits. ';

  insert into credential_vault_ssh_cert_key_bits_enm (bits)
  values
    (0),
    (2048),
    (3072),
    (4096),
    (256),
    (384),
    (521);

  create table credential_vault_ssh_cert_valid_key_type_key_bits (
    key_type text not null
      constraint credential_vault_ssh_cert_key_type_enm_fkey
        references credential_vault_ssh_cert_key_type_enm (name),
    key_bits int not null
      constraint credential_vault_ssh_cert_key_bits_enm_fkey
        references credential_vault_ssh_cert_key_bits_enm (bits),
    constraint credential_vault_ssh_cert_valid_key_type_key_bits_uq
      unique(key_type, key_bits)
  );

  insert into credential_vault_ssh_cert_valid_key_type_key_bits (key_type, key_bits)
  values
    ('ed25519', 0),
    ('ecdsa', 256),
    ('ecdsa', 384),
    ('ecdsa', 521),
    ('rsa', 2048),
    ('rsa', 3072),
    ('rsa', 4096);

  -- Updated in 99/01_credential_vault_library_refactor.up.sql
  create table credential_vault_ssh_cert_library (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_vault_store_fkey
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    vault_path text not null
      constraint vault_path_must_not_be_empty
        check(length(trim(vault_path)) > 0)
      constraint vault_path_must_be_sign_or_issue
        check(vault_path ~ '^.+\/(sign|issue)\/[^\/\\\s]+$'),
    username text not null
      constraint username_must_not_be_empty
        check(length(trim(username)) > 0),
    key_type text not null,
    key_bits int not null,
    ttl text,
    key_id text,
    critical_options bytea,
    extensions bytea,
    credential_type text,
    project_id wt_public_id not null,
    constraint credential_vault_ssh_cert_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_vault_ssh_cert_library_store_id_public_id_uq
      unique(store_id, public_id),
    constraint credential_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
      references credential_library (project_id, store_id, public_id, credential_type)
      on delete cascade
      on update cascade,
    constraint credential_vault_ssh_cert_valid_key_type_key_bits_fkey
      foreign key (key_type, key_bits)
      references credential_vault_ssh_cert_valid_key_type_key_bits(key_type, key_bits)
  );
  comment on table credential_vault_ssh_cert_library is
    'credential_vault_ssh_cert_library a credential library that issues credentials from a vault ssh secret backend.';

  -- Replaced in 82/07_vault_ssh_cert_default.up.sql
  create function default_ssh_certificate_credential_type() returns trigger
  as $$
  begin
    if new.credential_type is distinct from 'ssh_certificate' then
      raise warning 'credential_vault_ssh_cert_library only supports ssh_certificate credentials';
      new.credential_type = 'ssh_certificate';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function default_ssh_certificate_credential_type is
    'default_ssh_certificate_credential_type ensures the credential_type is set to ssh_certificate';

  create trigger default_ssh_certificate_credential_type before insert on credential_vault_ssh_cert_library
    for each row execute procedure default_ssh_certificate_credential_type();
  create trigger insert_credential_library_subtype before insert on credential_vault_ssh_cert_library
    for each row execute procedure insert_credential_library_subtype();
  create trigger default_create_time_column before insert on credential_vault_ssh_cert_library
    for each row execute procedure default_create_time();
  create trigger delete_credential_library_subtype after delete on credential_vault_ssh_cert_library
    for each row execute procedure delete_credential_library_subtype();
  create trigger immutable_columns before update on credential_vault_ssh_cert_library
    for each row execute procedure immutable_columns('public_id', 'store_id', 'project_id', 'credential_type', 'create_time');
  create trigger update_time_column before update on credential_vault_ssh_cert_library
    for each row execute procedure update_time_column();
  create trigger update_version_column after update on credential_vault_ssh_cert_library
    for each row execute procedure update_version_column();
  create trigger before_insert_credential_vault_library before insert on credential_vault_ssh_cert_library
    for each row execute procedure before_insert_credential_vault_library();

  insert into oplog_ticket (name, version)
  values
    ('credential_vault_ssh_cert_library', 1);

commit;
