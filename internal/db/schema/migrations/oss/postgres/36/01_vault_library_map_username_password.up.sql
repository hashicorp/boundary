-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

-- Renames table from 22/04_vault_library_map_user_password.up.sql
  alter table credential_vault_library_user_password_mapping_override
    rename to credential_vault_library_username_password_mapping_override;
  comment on table credential_vault_library_username_password_mapping_override is
    'credential_vault_library_username_password_mapping_override is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a username password credential type '
    'for a vault credential library.';

commit;
