-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index auth_ldap_managed_group_create_time_public_id_idx
      on auth_ldap_managed_group (create_time desc, public_id desc);
  create index auth_ldap_managed_group_update_time_public_id_idx
      on auth_ldap_managed_group (update_time desc, public_id desc);

  analyze auth_ldap_managed_group;

  -- Add new indexes for the create time and update time queries.
  create index auth_oidc_managed_group_create_time_public_id_idx
      on auth_oidc_managed_group (create_time desc, public_id desc);
  create index auth_oidc_managed_group_update_time_public_id_idx
      on auth_oidc_managed_group (update_time desc, public_id desc);

  analyze auth_oidc_managed_group;

commit;