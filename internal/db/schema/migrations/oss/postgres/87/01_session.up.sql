-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table session
    add column correlation_id uuid;

  -- Replaces trigger from 59/01_target_ingress_egress_worker_filters.up.sql
  drop trigger immutable_columns on session;
  create trigger immutable_columns before update on session
    for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'connection_limit',
    'create_time', 'endpoint', 'worker_filter', 'egress_worker_filter', 'ingress_worker_filter', 'correlation_id');

  -- Replaces view from 56/02_add_data_key_foreign_key_references.up.sql
  drop view credential_vault_credential_private;
  create view credential_vault_credential_private as
  select credential.public_id         as public_id,
         credential.library_id        as library_id,
         credential.session_id        as session_id,
         credential.create_time       as create_time,
         credential.update_time       as update_time,
         credential.version           as version,
         credential.external_id       as external_id,
         credential.last_renewal_time as last_renewal_time,
         credential.expiration_time   as expiration_time,
         credential.is_renewable      as is_renewable,
         credential.status            as status,
         credential.last_renewal_time + (credential.expiration_time - credential.last_renewal_time) / 2 as renewal_time,
         token.token_hmac             as token_hmac,
         token.token                  as ct_token, -- encrypted
         token.create_time            as token_create_time,
         token.update_time            as token_update_time,
         token.last_renewal_time      as token_last_renewal_time,
         token.expiration_time        as token_expiration_time,
         token.key_id                 as token_key_id,
         token.status                 as token_status,
         store.project_id             as project_id,
         store.vault_address          as vault_address,
         store.namespace              as namespace,
         store.ca_cert                as ca_cert,
         store.tls_server_name        as tls_server_name,
         store.tls_skip_verify        as tls_skip_verify,
         store.worker_filter          as worker_filter,
         cert.certificate             as client_cert,
         cert.certificate_key         as ct_client_key, -- encrypted
         cert.certificate_key_hmac    as client_cert_key_hmac,
         cert.key_id                  as client_key_id,
         sess.correlation_id          as session_correlation_id
    from credential_vault_credential credential
    join credential_vault_token token
      on credential.token_hmac = token.token_hmac
    join credential_vault_store store
      on token.store_id = store.public_id
    left join session sess
      on credential.session_id = sess.public_id
    left join credential_vault_client_certificate cert
      on store.public_id = cert.store_id
   where credential.expiration_time != 'infinity'::date;
  comment on view credential_vault_credential_private is
    'credential_vault_credential_private is a view where each row contains a credential, '
    'the vault token used to issue the credential, and the credential store data needed to connect to Vault. '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

commit;
