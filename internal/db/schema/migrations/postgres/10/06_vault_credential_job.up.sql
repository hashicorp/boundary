begin;

    create index credential_vault_token_expiration_time_ix
        on credential_vault_token(expiration_time);
    comment on index credential_vault_token_expiration_time_ix is
        'the credential_vault_token_expiration_time_ix is used by the token renewal job';

    create view credential_vault_job_renewable_tokens as
        select token_hmac,
               token, -- encrypted
               store_id,
               status,
               last_renewal_time,
               expiration_time,
               -- renewal time is the midpoint between the last renewal time and the expiration time
               last_renewal_time + (expiration_time - last_renewal_time) / 2 as renewal_time
        from credential_vault_token
        where status in ('current', 'maintaining');

    comment on view credential_vault_job_renewable_tokens is
        'credential_vault_renewable_tokens is a view where each row contains a token that is current or maintaining and should be renewed in Vault. '
        'Each row contains encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

    create view credential_vault_job_renewable_client_private as
    select store.public_id           as public_id,
           store.scope_id            as scope_id,
           store.name                as name,
           store.description         as description,
           store.vault_address       as vault_address,
           store.namespace           as namespace,
           store.ca_cert             as ca_cert,
           store.tls_server_name     as tls_server_name,
           store.tls_skip_verify     as tls_skip_verify,
           store.public_id           as store_id,
           token.token_hmac          as token_hmac,
           token.token               as ct_token, -- encrypted
           token.renewal_time        as renewal_time,
           token.status              as token_status,
           cert.certificate          as client_cert,
           cert.certificate_key      as ct_client_key, -- encrypted
           cert.certificate_key_hmac as client_cert_key_hmac,
           cert.key_id               as client_key_id
    from credential_vault_store store
             left join credential_vault_job_renewable_tokens token
                       on store.public_id = token.store_id
             left join credential_vault_client_certificate cert
                       on store.public_id = cert.store_id;
    comment on view credential_vault_job_renewable_client_private is
        'credential_vault_job_renewable_client_private is a view where each row contains a token that is current or maintaining, '
        'as well as the credential store''s data needed to connect to Vault. '
        'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

commit;
