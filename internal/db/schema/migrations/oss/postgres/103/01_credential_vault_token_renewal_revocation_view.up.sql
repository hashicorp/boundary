-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- public.credential_vault_token_renewal_revocation source

begin;

  drop view credential_vault_token_renewal_revocation;

  create view credential_vault_token_renewal_revocation as
  with
    tokens as (
      select token, -- encrypted
             token_hmac,
             store_id,
             -- renewal time is the midpoint between the last renewal time and the expiration time
             last_renewal_time + (expiration_time - last_renewal_time) / 2 as renewal_time,
             key_id,
             status,
             expiration_time
        from credential_vault_token
       where status in ('current', 'maintaining', 'revoke')
    )
    select store.public_id        as public_id,
           store.project_id       as project_id,
           store.vault_address    as vault_address,
           store.namespace        as namespace,
           store.ca_cert          as ca_cert,
           store.tls_server_name  as tls_server_name,
           store.tls_skip_verify  as tls_skip_verify,
           store.worker_filter    as worker_filter,
           store.delete_time      as delete_time,
           token.token            as ct_token, -- encrypted
           token.token_hmac       as token_hmac,
           token.renewal_time     as token_renewal_time,
           token.key_id           as token_key_id,
           token.status           as token_status,
           token.expiration_time  as token_expiration_time,
           cert.certificate       as client_cert,
           cert.certificate_key   as ct_client_key, -- encrypted
           cert.key_id            as client_key_id
      from credential_vault_store store
      join tokens token
        on store.public_id = token.store_id
      left join credential_vault_client_certificate cert
        on store.public_id = cert.store_id;
   comment on view credential_vault_token_renewal_revocation is
      'credential_vault_token_renewal_revocation is a view where each row contains a credential store and the credential store''s data needed to connect to Vault. '
      'The view returns a separate row for each active token in Vault (current, maintaining and revoke tokens); this view should only be used for token renewal and revocation. '
      'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

commit;