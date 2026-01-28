-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_type_enm (
    name text primary key
      -- This constraint is replaced in 32/01_credential_type.up.sql
      constraint only_predefined_credential_types_allowed
      check (
        name in (
          'unspecified',
          'user_password'
        )
      )
  );
  comment on table credential_type_enm is
    'credential_type_enm is an enumeration table for the types of credentials a credential library can provide.';

  insert into credential_type_enm (name)
  values
    ('unspecified'),
    ('user_password');

  -- Add a credential_type column to the base credential_library table and the
  -- credential_vault_library subtype table.

  alter table credential_library
    add column credential_type text not null default 'unspecified'
      constraint credential_type_enm_fkey
        references credential_type_enm (name)
        on delete restrict
        on update cascade,
    add constraint credential_library_store_id_public_id_credential_type_uq
      unique(store_id, public_id, credential_type)
  ;

  alter table credential_vault_library
    add column credential_type text not null default 'unspecified'
      constraint credential_type_enm_fkey
        references credential_type_enm (name)
        on delete restrict
        on update cascade,
    drop constraint credential_library_fkey,
    add constraint credential_library_fkey
      foreign key (store_id, public_id, credential_type)
      references credential_library (store_id, public_id, credential_type)
      on delete cascade
      on update cascade
  ;

  -- This drops a constraint that is no longer needed.
  -- It could not be dropped until after the credential_library_fkey constraint was
  -- dropped and then recreated.
  alter table credential_library
    drop constraint credential_library_store_id_public_id_uq
  ;

  -- Drop and recreate the insert trigger function for credential_library subtypes.

  drop trigger insert_credential_library_subtype on credential_vault_library;
  drop function insert_credential_library_subtype();

  -- insert_credential_library_subtype() is a before insert trigger
  -- function for subtypes of credential_library
  -- Replaced in 46/01_credential.up.sql
  create function insert_credential_library_subtype() returns trigger
  as $$
  begin
    insert into credential_library
      (public_id, store_id, credential_type)
    values
      (new.public_id, new.store_id, new.credential_type);
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_credential_library_subtype before insert on credential_vault_library
    for each row execute procedure insert_credential_library_subtype();

commit;
