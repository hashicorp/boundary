-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Updated in 36/01_vault_library_map_username_password.up.sql
  -- Renamed in 99/01_credential_vault_library_refactor.up.sql
  create table credential_vault_library_user_password_mapping_override (
    library_id wt_public_id primary key
      constraint credential_vault_library_fkey
        references credential_vault_library (public_id)
        on delete cascade
        on update cascade
      constraint credential_vault_library_mapping_override_fkey
        references credential_vault_library_mapping_override (library_id)
        on delete cascade
        on update cascade,
    username_attribute wt_sentinel
      default wt_to_sentinel('no override')
      not null,
    password_attribute wt_sentinel
      default wt_to_sentinel('no override')
      not null
  );
  comment on table credential_vault_library_user_password_mapping_override is
    'credential_vault_library_user_password_mapping_override is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a user password credential type '
    'for a vault credential library.';

  create trigger insert_credential_vault_library_mapping_override_subtype before insert on credential_vault_library_user_password_mapping_override
    for each row execute procedure insert_credential_vault_library_mapping_override_subtype();

  create trigger delete_credential_vault_library_mapping_override_subtype after delete on credential_vault_library_user_password_mapping_override
    for each row execute procedure delete_credential_vault_library_mapping_override_subtype();

commit;
