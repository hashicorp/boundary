begin;

  -- drop constraint so we can add ssh_certificate
  alter table credential_type_enm
    drop constraint only_predefined_credential_types_allowed;

  -- Add new constraint that only allows known types
  -- This replaces the constraint defined in 39/01_static_ssh_private_key_creds_up
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
        check(length(trim(vault_path)) > 0),
    username text not null,
    key_type text not null
      default 'ed25519'
      constraint credential_vault_ssh_cert_key_type_enm_fkey
        references credential_vault_ssh_cert_key_type_enm (name),
    key_bits int,
    ttl text,
    key_id text,
    critical_options bytea,
    extensions bytea,
    credential_type text default 'ssh_certificate',
      -- constraint credential_type_must_be_ssh_cert
      -- check (type is only 'ssh_certificate' )
    project_id wt_public_id not null,
    constraint credential_vault_ssh_cert_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
      references credential_library (project_id, store_id, public_id, credential_type)
      on delete cascade
      on update cascade,
    constraint credential_vault_ssh_cert_library_store_id_public_id_uq
      unique(store_id, public_id)
  );

  insert into oplog_ticket (name, version)
  values
    ('credential_vault_ssh_cert_library', 1);

  create trigger insert_credential_library_subtype before insert on credential_vault_ssh_cert_library
    for each row execute procedure insert_credential_library_subtype();

commit;
