begin;

  alter table auth_token
    rename column key_id to key_version_id;

  alter table auth_password_argon2_cred
    rename column key_id to key_version_id;

  alter table session
    rename column key_id to key_version_id;

  alter table credential_vault_token
    rename column key_id to key_version_id;

  alter table credential_vault_client_certificate
    rename column key_id to key_version_id;

  alter table auth_oidc_method
    rename column key_id to key_version_id;

  alter table host_plugin_catalog_secret
    rename column key_id to key_version_id;

  alter table session_credential
    rename column key_id to key_version_id;

  alter table credential_static_username_password_credential
    rename column key_id to key_version_id;

  alter table worker_auth_ca_certificate
    rename column key_id to key_version_id;

  alter table worker_auth_authorized
    rename column key_id to key_version_id;

  alter table credential_static_ssh_private_key_credential
    rename column key_id to key_version_id;

commit;
