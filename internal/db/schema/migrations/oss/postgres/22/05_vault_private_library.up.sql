-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Updated in 36/02_vault_private_library.up.sql
-- Replaces view from 10/04_vault_credential.up.sql
     drop view credential_vault_library_private;

     create view credential_vault_library_private as
     with
     password_override (library_id, username_attribute, password_attribute) as (
       select library_id,
              nullif(username_attribute, wt_to_sentinel('no override')),
              nullif(password_attribute, wt_to_sentinel('no override'))
         from credential_vault_library_user_password_mapping_override
     )
     select library.public_id         as public_id,
            library.store_id          as store_id,
            library.name              as name,
            library.description       as description,
            library.create_time       as create_time,
            library.update_time       as update_time,
            library.version           as version,
            library.vault_path        as vault_path,
            library.http_method       as http_method,
            library.http_request_body as http_request_body,
            library.credential_type   as credential_type,
            store.scope_id            as scope_id,
            store.vault_address       as vault_address,
            store.namespace           as namespace,
            store.ca_cert             as ca_cert,
            store.tls_server_name     as tls_server_name,
            store.tls_skip_verify     as tls_skip_verify,
            store.token_hmac          as token_hmac,
            store.ct_token            as ct_token, -- encrypted
            store.token_key_id        as token_key_id,
            store.client_cert         as client_cert,
            store.ct_client_key       as ct_client_key, -- encrypted
            store.client_key_id       as client_key_id,
            upasso.username_attribute as username_attribute,
            upasso.password_attribute as password_attribute
       from credential_vault_library library
       join credential_vault_store_private store
         on library.store_id = store.public_id
  left join password_override upasso
         on library.public_id = upasso.library_id
        and store.token_status = 'current';
  comment on view credential_vault_library_private is
    'credential_vault_library_private is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

     create view credential_vault_library_public as
     select public_id,
            store_id,
            name,
            description,
            create_time,
            update_time,
            version,
            vault_path,
            http_method,
            http_request_body,
            credential_type,
            username_attribute,
            password_attribute
       from credential_vault_library_private;
  comment on view credential_vault_library_public is
    'credential_vault_library_public is a view where each row contains a credential library and any of library''s credential mapping overrides. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

commit;
