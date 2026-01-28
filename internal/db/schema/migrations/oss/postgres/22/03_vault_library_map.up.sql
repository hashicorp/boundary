-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Renamed in 99/01_credential_vault_library_refactor.up.sql
  create table credential_vault_library_mapping_override (
    library_id wt_public_id primary key
      constraint credential_vault_library_fkey
        references credential_vault_library (public_id)
        on delete cascade
        on update cascade
  );
  comment on table credential_vault_library_mapping_override is
    'credential_vault_library_mapping_override is a base table for the vault library mapping override type. '
    'Each row is owned by a single vault library and maps 1-to-1 to a row in one of the vault library mapping override subtype tables.';

  -- insert_credential_vault_library_mapping_override_subtype() is a before insert trigger
  -- function for subtypes of credential_vault_library_mapping_override
  -- Updated and renamed in 99/01_credential_vault_library_refactor.up.sql
  create function insert_credential_vault_library_mapping_override_subtype() returns trigger
  as $$
  begin
    insert into credential_vault_library_mapping_override
      (library_id)
    values
      (new.library_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_vault_library_mapping_override_subtype() is an after delete trigger
  -- function for subtypes of credential_vault_library_mapping_override
  -- Updated and renamed in 99/01_credential_vault_library_refactor.up.sql
  create function delete_credential_vault_library_mapping_override_subtype() returns trigger
  as $$
  begin
    delete from credential_vault_library_mapping_override
    where library_id = old.library_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

commit;
