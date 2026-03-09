-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table auth_token
    alter column key_id type kms_private_id,
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  alter table auth_password_argon2_cred
    alter column key_id type kms_private_id,
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  -- Some existing sessions may exist with an empty key_id
  update session
     set key_id = null
   where key_id = '';

  alter table session
    -- cannot set key_id type to kms_private_id because the kms_private_id type
    -- has a 'not null' restriction and the key_id can be null in the session
    -- table.
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  -- Replaces trigger from 44/04_session.up.sql
  -- Replaced in 60/02_sessions.up.sql
  -- Adding a foreign key reference to the kms key means we have
  -- to set the key_id to null when the scope_id is set to null,
  -- otherwise we can't delete scopes with sessions, since deleting
  -- the scope cascade deletes the key referenced by key_id.
  create or replace function cancel_session_with_null_fk() returns trigger
  as $$
  begin
    -- Note that we need each of these to run in case
    -- more than one of them is null.
    if new.user_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.host_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.target_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.host_set_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.auth_token_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.project_id is null then
      -- Setting the key_id to null will allow the scope
      -- to cascade delete its keys.
      new.key_id = null;
      perform cancel_session(new.public_id);
    end if;
    return new;
  end;
  $$ language plpgsql;


  -- we drop some views, so we can recreate them after changing the type of the referencing columns.
  drop view
    oidc_auth_method_with_value_obj,
    host_plugin_catalog_with_secret,
    credential_vault_store_client,
    credential_vault_library_issue_credentials,
    credential_vault_token_renewal_revocation,
    credential_vault_credential_private;

  alter table auth_oidc_method
    alter column key_id type kms_private_id;

  alter table host_plugin_catalog_secret
    alter column key_id type kms_private_id;

  alter table credential_vault_token
    alter column key_id type kms_private_id;

  alter table credential_vault_client_certificate
    alter column key_id type kms_private_id;

  alter table session_credential
    alter column key_id type kms_private_id;

  alter table credential_static_username_password_credential
    alter column key_id type kms_private_id;

  alter table credential_static_ssh_private_key_credential
    alter column key_id type kms_private_id;


-- Recreated in 79/01_auth_oidc_prompt.up.sql
  create view oidc_auth_method_with_value_obj as 
  select
    case when s.primary_auth_method_id is not null then
      true
    else false end
    as is_primary_auth_method,
    am.public_id,
    am.scope_id,
    am.name,
    am.description,
    am.create_time,
    am.update_time,
    am.version,
    am.state,
    am.api_url,
    am.disable_discovered_config_validation,
    am.issuer,
    am.client_id,
    am.client_secret,
    am.client_secret_hmac,
    am.key_id,
    am.max_age,
    -- the string_agg(..) column will be null if there are no associated value objects
    string_agg(distinct alg.signing_alg_name, '|') as algs,
    string_agg(distinct aud.aud_claim, '|') as auds,
    string_agg(distinct cert.certificate, '|') as certs,
    string_agg(distinct cs.scope, '|') as claims_scopes,
    string_agg(distinct concat_ws('=', acm.from_claim, acm.to_claim), '|') as account_claim_maps
  from 	
    auth_oidc_method am 
    left outer join iam_scope                   s     on am.public_id = s.primary_auth_method_id 
    left outer join auth_oidc_signing_alg       alg   on am.public_id = alg.oidc_method_id
    left outer join auth_oidc_aud_claim         aud   on am.public_id = aud.oidc_method_id
    left outer join auth_oidc_certificate       cert  on am.public_id = cert.oidc_method_id
    left outer join auth_oidc_scope             cs    on am.public_id = cs.oidc_method_id
    left outer join auth_oidc_account_claim_map acm   on am.public_id = acm.oidc_method_id
  group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
  comment on view oidc_auth_method_with_value_obj is
  'oidc auth method with its associated value objects (algs, auds, certs, scopes) as columns with | delimited values';

  -- Replaced by 92/01_host_plugin_catalog_worker_filter.up.sql
  create view host_plugin_catalog_with_secret as
  select
    hc.public_id,
    hc.project_id,
    hc.plugin_id,
    hc.name,
    hc.description,
    hc.create_time,
    hc.update_time,
    hc.version,
    hc.secrets_hmac,
    hc.attributes,
    hcs.secret,
    hcs.key_id,
    hcs.create_time as persisted_create_time,
    hcs.update_time as persisted_update_time
  from
    host_plugin_catalog hc
      left outer join host_plugin_catalog_secret hcs   on hc.public_id = hcs.catalog_id;
  comment on view host_plugin_catalog_with_secret is
    'host plugin catalog with its associated persisted data';
  
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

  -- Replaced in 63/02_add_ssh_cert_to_vault_cred_library_view.up.sql
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

  -- Replaced in 87/01_session.up.sql
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
            cert.certificate             as client_cert,
            cert.certificate_key         as ct_client_key, -- encrypted
            cert.certificate_key_hmac    as client_cert_key_hmac,
            cert.key_id                  as client_key_id
       from credential_vault_credential credential
       join credential_vault_token token
         on credential.token_hmac = token.token_hmac
       join credential_vault_store store
         on token.store_id = store.public_id
  left join credential_vault_client_certificate cert
         on store.public_id = cert.store_id
      where credential.expiration_time != 'infinity'::date;
  comment on view credential_vault_credential_private is
    'credential_vault_credential_private is a view where each row contains a credential, '
    'the vault token used to issue the credential, and the credential store data needed to connect to Vault. '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

commit;
