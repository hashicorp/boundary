-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- updated in 39/01_static_ssh_private_key_creds
  -- drop constraint so we can migrate user_password to username_password
  alter table credential_type_enm
    drop constraint only_predefined_credential_types_allowed;

  -- Next: we will update user_password to username_password
  update credential_type_enm
    set name = 'username_password'
  where name = 'user_password';

  -- Add new constraint that only allows unspecified and new username_password
  -- This replaces the constraint defined in 2/02_credential_type.up.sql
  alter table credential_type_enm
    add constraint only_predefined_credential_types_allowed
      check (
        name in (
          'unspecified',
          'username_password'
        )
      );

commit;
