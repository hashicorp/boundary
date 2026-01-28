-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select has_index('auth_ldap_managed_group', 'auth_ldap_managed_group_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_ldap_managed_group', 'auth_ldap_managed_group_update_time_public_id_idx', array['update_time', 'public_id']);

  select has_index('auth_oidc_managed_group', 'auth_oidc_managed_group_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_oidc_managed_group', 'auth_oidc_managed_group_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;