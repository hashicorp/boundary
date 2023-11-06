-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create index auth_ldap_account_update_time_idx on auth_ldap_account (update_time);
  create index auth_ldap_managed_group_update_time_idx on auth_ldap_managed_group (update_time);
  create index auth_ldap_method_update_time_idx on auth_ldap_method (update_time);
  create index auth_oidc_account_update_time_idx on auth_oidc_account (update_time);
  create index auth_oidc_managed_group_update_time_idx on auth_oidc_managed_group (update_time);
  create index auth_oidc_method_update_time_idx on auth_oidc_method (update_time);
  create index auth_password_account_update_time_idx on auth_password_account (update_time);
  create index auth_password_method_update_time_idx on auth_password_method (update_time);
  create index auth_token_update_time_idx on auth_token (update_time);
  create index credential_static_json_credential_update_time_idx on credential_static_json_credential (update_time);
  create index credential_static_ssh_private_key_credential_update_time_idx on credential_static_ssh_private_key_credential (update_time);
  create index credential_static_store_update_time_idx on credential_static_store (update_time);
  create index credential_static_username_password_credential_update_time_idx on credential_static_username_password_credential (update_time);
  create index credential_vault_library_update_time_idx on credential_vault_library (update_time);
  create index credential_vault_ssh_cert_library_update_time_idx on credential_vault_ssh_cert_library (update_time);
  create index credential_vault_store_update_time_idx on credential_vault_store (update_time);
  create index host_plugin_catalog_update_time_idx on host_plugin_catalog (update_time);
  create index host_plugin_host_update_time_idx on host_plugin_host (update_time);
  create index host_plugin_set_update_time_idx on host_plugin_set (update_time);
  create index iam_group_update_time_idx on iam_group (update_time);
  create index iam_role_update_time_idx on iam_role (update_time);
  create index iam_scope_update_time_idx on iam_scope (update_time);
  create index iam_user_update_time_idx on iam_user (update_time);
  create index recording_session_update_time_idx on recording_session (update_time);
  create index server_worker_update_time_idx on server_worker (update_time);
  create index session_update_time_idx on session (update_time);
  create index static_host_catalog_update_time_idx on static_host_catalog (update_time);
  create index static_host_update_time_idx on static_host (update_time);
  create index static_host_set_update_time_idx on static_host_set (update_time);
  create index storage_plugin_storage_bucket_update_time_idx on storage_plugin_storage_bucket (update_time);
  create index target_ssh_update_time_idx on target_ssh (update_time);
  create index target_tcp_update_time_idx on target_tcp (update_time);

commit;
