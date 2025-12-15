-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- update views
  drop view credential_vault_store_public;
  drop view credential_vault_library_public;
  drop view credential_vault_library_private;
  drop view credential_vault_store_private;

  -- Recreated in 56/02_add_data_key_foreign_key_references.up.sql
  create view credential_vault_token_renewal_revocation as
  with
    tokens as (
      select token, -- encrypted
             token_hmac,
             store_id,
             -- renewal time is the midpoint between the last renewal time and the expiration time
             last_renewal_time + (expiration_time - last_renewal_time) / 2 as renewal_time,
             key_id,
             status
      from credential_vault_token
     where status in ('current', 'maintaining', 'revoke')
    )
  select store.public_id       as public_id,
         store.project_id      as project_id,
         store.vault_address   as vault_address,
         store.namespace       as namespace,
         store.ca_cert         as ca_cert,
         store.tls_server_name as tls_server_name,
         store.tls_skip_verify as tls_skip_verify,
         store.worker_filter   as worker_filter,
         store.delete_time     as delete_time,
         token.token           as ct_token, -- encrypted
         token.token_hmac      as token_hmac,
         token.renewal_time    as token_renewal_time,
         token.key_id          as token_key_id,
         token.status          as token_status,
         cert.certificate      as client_cert,
         cert.certificate_key  as ct_client_key, -- encrypted
         cert.key_id           as client_key_id
  from credential_vault_store store
  join tokens token
    on store.public_id = token.store_id
  left join credential_vault_client_certificate cert
    on store.public_id = cert.store_id;
  comment on view credential_vault_token_renewal_revocation is
    'credential_vault_token_renewal_revocation is a view where each row contains a credential store and the credential store''s data needed to connect to Vault. '
    'The view returns a separate row for each active token in Vault (current, maintaining and revoke tokens); this view should only be used for token renewal and revocation. '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

  create view credential_vault_store_list_lookup as
  select store.public_id                   as public_id,
         store.project_id                  as project_id,
         store.name                        as name,
         store.description                 as description,
         store.create_time                 as create_time,
         store.update_time                 as update_time,
         store.delete_time                 as delete_time,
         store.version                     as version,
         store.vault_address               as vault_address,
         store.namespace                   as namespace,
         store.ca_cert                     as ca_cert,
         store.tls_server_name             as tls_server_name,
         store.tls_skip_verify             as tls_skip_verify,
         store.worker_filter               as worker_filter,
         token.token_hmac                  as token_hmac,
         coalesce(token.status, 'expired') as token_status,
         cert.certificate                  as client_cert,
         cert.certificate_key_hmac         as client_cert_key_hmac
    from credential_vault_store store
    left join credential_vault_token token
      on store.public_id = token.store_id
     and token.status = 'current'
    left join credential_vault_client_certificate cert
      on store.public_id = cert.store_id
   where store.delete_time is null;
  comment on view credential_vault_store_list_lookup is
    'credential_vault_store_list_lookup is a view where each row contains a credential store. '
    'If the Vault token has expired this view will return an empty token_hmac and a token_status of ''expired'' '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

  -- Recreated in 56/02_add_data_key_foreign_key_references.up.sql
  create view credential_vault_store_client as
  select store.public_id                   as public_id,
         store.project_id                  as project_id,
         store.vault_address               as vault_address,
         store.namespace                   as namespace,
         store.ca_cert                     as ca_cert,
         store.tls_server_name             as tls_server_name,
         store.tls_skip_verify             as tls_skip_verify,
         store.worker_filter               as worker_filter,
         token.token                       as ct_token, -- encrypted
         token.token_hmac                  as token_hmac,
         coalesce(token.status, 'expired') as token_status,
         token.key_id                      as token_key_id,
         cert.certificate                  as client_cert,
         cert.certificate_key              as ct_client_key, -- encrypted
         cert.key_id                       as client_key_id
    from credential_vault_store store
    left join credential_vault_token token
      on store.public_id = token.store_id
     and token.status = 'current'
    left join credential_vault_client_certificate cert
      on store.public_id = cert.store_id
   where store.delete_time is null;
  comment on view credential_vault_store_client is
    'credential_vault_store_client is a view where each row contains a credential store and the credential store''s data needed to connect to Vault. '
    'The view returns the current token for the store, if the Vault token has expired this view will return an empty token_hmac and a token_status of ''expired''  '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

  -- Recreated in 56/02_add_data_key_foreign_key_references.up.sql
  create view credential_vault_library_issue_credentials as
  with
    password_override (library_id, username_attribute, password_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(password_attribute, wt_to_sentinel('no override'))
      from credential_vault_library_username_password_mapping_override
    ),
    ssh_private_key_override (library_id, username_attribute, private_key_attribute, private_key_passphrase_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(private_key_attribute, wt_to_sentinel('no override')),
        nullif(private_key_passphrase_attribute, wt_to_sentinel('no override'))
      from credential_vault_library_ssh_private_key_mapping_override
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
         store.project_id          as project_id,
         store.vault_address       as vault_address,
         store.namespace           as namespace,
         store.ca_cert             as ca_cert,
         store.tls_server_name     as tls_server_name,
         store.tls_skip_verify     as tls_skip_verify,
         store.worker_filter       as worker_filter,
         store.ct_token            as ct_token, -- encrypted
         store.token_hmac          as token_hmac,
         store.token_status        as token_status,
         store.token_key_id        as token_key_id,
         store.client_cert         as client_cert,
         store.ct_client_key       as ct_client_key, -- encrypted
         store.client_key_id       as client_key_id,
         coalesce(upasso.username_attribute,sshpk.username_attribute)
             as username_attribute,
         upasso.password_attribute              as password_attribute,
         sshpk.private_key_attribute            as private_key_attribute,
         sshpk.private_key_passphrase_attribute as private_key_passphrase_attribute
    from credential_vault_library library
    join credential_vault_store_client store
      on library.store_id = store.public_id
    left join password_override upasso
      on library.public_id = upasso.library_id
    left join ssh_private_key_override sshpk
      on library.public_id = sshpk.library_id;
  comment on view credential_vault_library_issue_credentials is
    'credential_vault_library_issue_credentials is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
    'This view should only be used when issuing credentials from a Vault credential library. Each row may contain encrypted data. '
    'This view should not be used to retrieve data which will be returned external to boundary.';

  -- Replaced in 98/02_username_password_domain_vault.up.sql
  create view credential_vault_library_list_lookup as
  with
    password_override (library_id, username_attribute, password_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(password_attribute, wt_to_sentinel('no override'))
      from credential_vault_library_username_password_mapping_override
    ),
    ssh_private_key_override (library_id, username_attribute, private_key_attribute, private_key_passphrase_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(private_key_attribute, wt_to_sentinel('no override')),
        nullif(private_key_passphrase_attribute, wt_to_sentinel('no override'))
      from credential_vault_library_ssh_private_key_mapping_override
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
         coalesce(upasso.username_attribute,sshpk.username_attribute)
                                   as username_attribute,
         upasso.password_attribute              as password_attribute,
         sshpk.private_key_attribute            as private_key_attribute,
         sshpk.private_key_passphrase_attribute as private_key_passphrase_attribute
    from credential_vault_library library
    left join password_override upasso
      on library.public_id = upasso.library_id
    left join ssh_private_key_override sshpk
      on library.public_id = sshpk.library_id;
  comment on view credential_vault_library_list_lookup is
    'credential_vault_library_list_lookup is a view where each row contains a credential library and any of library''s credential mapping overrides. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

commit;
