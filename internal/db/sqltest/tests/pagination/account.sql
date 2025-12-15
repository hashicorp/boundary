-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(6);

  select has_index('auth_ldap_account', 'auth_ldap_account_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_ldap_account', 'auth_ldap_account_update_time_public_id_idx', array['update_time', 'public_id']);

  select has_index('auth_oidc_account', 'auth_oidc_account_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_oidc_account', 'auth_oidc_account_update_time_public_id_idx', array['update_time', 'public_id']);
  
  select has_index('auth_password_account', 'auth_password_account_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_password_account', 'auth_password_account_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;