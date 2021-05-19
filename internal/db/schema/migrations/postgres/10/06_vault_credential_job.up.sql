begin;

    create view credential_vault_job_renewable_tokens as
        select token_hmac,
               token, -- encrypted
               store_id,
               -- renewal time is the midpoint between the last renewal time and the expiration time
               last_renewal_time + (expiration_time - last_renewal_time) / 2 renewal_time
        from credential_vault_token
        where status in ('current', 'maintaining');

    comment on view credential_vault_job_renewable_tokens is
        'credential_vault_renewable_tokens is a view where each row contains a token that is current or maintaining and should be renewed in Vault. '
            'Each row contains encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

commit;
