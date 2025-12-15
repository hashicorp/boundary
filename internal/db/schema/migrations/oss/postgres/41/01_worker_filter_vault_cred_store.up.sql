-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Add worker_filter to vault cred store table and related views
alter table credential_vault_store
  add column worker_filter wt_bexprfilter;

drop view credential_vault_library_public;
drop view credential_vault_library_private;
drop view credential_vault_store_public;
drop view credential_vault_store_private;

-- Replaces view from 10/04_vault_credential.up.sql
-- Updated in 44/01_credentials.up.sql
create view credential_vault_store_private as
with
  active_tokens as (
    select token_hmac,
           token, -- encrypted
           store_id,
           create_time,
           update_time,
           last_renewal_time,
           expiration_time,
           -- renewal time is the midpoint between the last renewal time and the expiration time
           last_renewal_time + (expiration_time - last_renewal_time) / 2 as renewal_time,
           key_id,
           status
    from credential_vault_token
    where status in ('current', 'maintaining', 'revoke')
  )
select store.public_id           as public_id,
       store.scope_id            as scope_id,
       store.name                as name,
       store.description         as description,
       store.create_time         as create_time,
       store.update_time         as update_time,
       store.delete_time         as delete_time,
       store.version             as version,
       store.vault_address       as vault_address,
       store.namespace           as namespace,
       store.ca_cert             as ca_cert,
       store.tls_server_name     as tls_server_name,
       store.tls_skip_verify     as tls_skip_verify,
       store.public_id           as store_id,
       store.worker_filter       as worker_filter,
       token.token_hmac          as token_hmac,
       token.token               as ct_token, -- encrypted
       token.create_time         as token_create_time,
       token.update_time         as token_update_time,
       token.last_renewal_time   as token_last_renewal_time,
       token.expiration_time     as token_expiration_time,
       token.renewal_time        as token_renewal_time,
       token.key_id              as token_key_id,
       token.status              as token_status,
       cert.certificate          as client_cert,
       cert.certificate_key      as ct_client_key, -- encrypted
       cert.certificate_key_hmac as client_cert_key_hmac,
       cert.key_id               as client_key_id
from credential_vault_store store
       left join active_tokens token
                 on store.public_id = token.store_id
       left join credential_vault_client_certificate cert
                 on store.public_id = cert.store_id;
comment on view credential_vault_store_private is
  'credential_vault_store_private is a view where each row contains a credential store and the credential store''s data needed to connect to Vault. '
  'The view returns a separate row for each current, maintaining and revoke token; maintaining tokens should only be used for token/credential renewal and revocation. '
  'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

-- Replaces view from 10/04_vault_credential.up.sql
-- Updated in 44/01_credentials.up.sql
create view credential_vault_store_public as
select public_id,
       scope_id,
       name,
       description,
       create_time,
       update_time,
       version,
       vault_address,
       namespace,
       ca_cert,
       tls_server_name,
       tls_skip_verify,
       worker_filter,
       token_hmac,
       token_create_time,
       token_update_time,
       token_last_renewal_time,
       token_expiration_time,
       client_cert,
       client_cert_key_hmac
from credential_vault_store_private
where token_status = 'current'
  and delete_time is null;
comment on view credential_vault_store_public is
  'credential_vault_store_public is a view where each row contains a credential store. '
  'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

-- Replaces view from 39/02_vault_ssh_private_key_override.up.sql
-- Replaced in 42/01_ssh_private_key_passphrase.up.sql
create view credential_vault_library_private as
with
  password_override (library_id, username_attribute, password_attribute) as (
    select library_id,
           nullif(username_attribute, wt_to_sentinel('no override')),
           nullif(password_attribute, wt_to_sentinel('no override'))
    from credential_vault_library_username_password_mapping_override
  ),
  ssh_private_key_override (library_id, username_attribute, private_key_attribute) as (
    select library_id,
           nullif(username_attribute, wt_to_sentinel('no override')),
           nullif(private_key_attribute, wt_to_sentinel('no override'))
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
       store.scope_id            as scope_id,
       store.vault_address       as vault_address,
       store.namespace           as namespace,
       store.ca_cert             as ca_cert,
       store.tls_server_name     as tls_server_name,
       store.tls_skip_verify     as tls_skip_verify,
       store.worker_filter       as worker_filter,
       store.token_hmac          as token_hmac,
       store.ct_token            as ct_token, -- encrypted
       store.token_key_id        as token_key_id,
       store.client_cert         as client_cert,
       store.ct_client_key       as ct_client_key, -- encrypted
       store.client_key_id       as client_key_id,
       coalesce(upasso.username_attribute,sshpk.username_attribute)
                                 as username_attribute,
       upasso.password_attribute    as password_attribute,
       sshpk.private_key_attribute  as private_key_attribute
from credential_vault_library library
       join credential_vault_store_private store
            on library.store_id = store.public_id
       left join password_override upasso
                 on library.public_id = upasso.library_id
                   and store.token_status = 'current'
       left join ssh_private_key_override sshpk
                 on library.public_id = sshpk.library_id
                   and store.token_status = 'current';
comment on view credential_vault_library_private is
  'credential_vault_library_private is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
  'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

-- Replaces view from 39/02_vault_ssh_private_key_override.up.sql
-- Replaced in 42/01_ssh_private_key_passphrase.up.sql
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
       worker_filter,
       username_attribute,
       password_attribute,
       private_key_attribute
from credential_vault_library_private;
comment on view credential_vault_library_public is
  'credential_vault_library_public is a view where each row contains a credential library and any of library''s credential mapping overrides. '
  'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

drop view credential_vault_credential_private;
-- Replaces view from 10/04_vault_credential.up.sql
-- Updated in 44/01_credentials.up.sql
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
       store.scope_id               as scope_id,
       store.vault_address          as vault_address,
       store.namespace              as namespace,
       store.ca_cert                as ca_cert,
       store.tls_server_name        as tls_server_name,
       store.tls_skip_verify        as tls_skip_verify,
       store.worker_filter          as worker_filter,
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