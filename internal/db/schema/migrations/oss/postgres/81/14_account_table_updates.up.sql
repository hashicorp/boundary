-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index auth_ldap_account_create_time_public_id_idx
      on auth_ldap_account (create_time desc, public_id desc);
  create index auth_ldap_account_update_time_public_id_idx
      on auth_ldap_account (update_time desc, public_id desc);

  analyze auth_ldap_account;

  -- Add new indexes for the create time and update time queries.
  create index auth_oidc_account_create_time_public_id_idx
      on auth_oidc_account (create_time desc, public_id desc);
  create index auth_oidc_account_update_time_public_id_idx
      on auth_oidc_account (update_time desc, public_id desc);

  analyze auth_oidc_account;

  -- Add new indexes for the create time and update time queries.
  create index auth_password_account_create_time_public_id_idx
      on auth_password_account (create_time desc, public_id desc);
  create index auth_password_account_update_time_public_id_idx
      on auth_password_account (update_time desc, public_id desc);

  analyze auth_password_account;

commit;