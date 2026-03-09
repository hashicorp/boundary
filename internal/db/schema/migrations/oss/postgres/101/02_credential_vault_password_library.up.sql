-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_vault_generic_library_password_mapping_override (
    library_id wt_public_id primary key
      constraint credential_vault_generic_library_fkey
        references credential_vault_generic_library (public_id)
        on delete cascade
        on update cascade
      constraint credential_vault_generic_library_mapping_override_fkey
        references credential_vault_generic_library_mapping_override (library_id)
        on delete cascade
        on update cascade,
    password_attribute wt_sentinel
      default wt_to_sentinel('no override')
      not null
  );
  comment on table credential_vault_generic_library_password_mapping_override is
    'credential_vault_generic_library_password_mapping_override is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a password credential type '
    'for a vault credential library.';

  create trigger insert_credential_vault_generic_library_mapping_override_subtyp before insert on credential_vault_generic_library_password_mapping_override
    for each row execute procedure insert_credential_vault_generic_library_mapping_override_subtyp();

  create trigger delete_credential_vault_generic_library_mapping_override_subtyp after delete on credential_vault_generic_library_password_mapping_override
    for each row execute procedure delete_credential_vault_generic_library_mapping_override_subtyp();

  -- Replaces view from 100/01_credential_vault_ldap_library.up.sql
  drop view credential_vault_library_issue_credentials;
  create view credential_vault_library_issue_credentials as
    with
      username_password_override (library_id, username_attribute, password_attribute) as (
        select library_id,
          nullif(username_attribute, wt_to_sentinel('no override')),
          nullif(password_attribute, wt_to_sentinel('no override'))
        from credential_vault_generic_library_username_password_mapping_ovrd
      ),
      ssh_private_key_override (library_id, username_attribute, private_key_attribute, private_key_passphrase_attribute) as (
        select library_id,
          nullif(username_attribute, wt_to_sentinel('no override')),
          nullif(private_key_attribute, wt_to_sentinel('no override')),
          nullif(private_key_passphrase_attribute, wt_to_sentinel('no override'))
        from credential_vault_generic_library_ssh_private_key_mapping_ovrd
      ),
      username_password_domain_override (library_id, username_attribute, password_attribute, domain_attribute) as (
        select library_id,
          nullif(username_attribute, wt_to_sentinel('no override')),
          nullif(password_attribute, wt_to_sentinel('no override')),
          nullif(domain_attribute, wt_to_sentinel('no override'))
        from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
      ),
      password_override (library_id, password_attribute) as (
        select library_id,
          nullif(password_attribute, wt_to_sentinel('no override'))
        from credential_vault_generic_library_password_mapping_override
      )
    select library.public_id    as public_id,
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
      null                      as key_type,
      null                      as key_bits,
      null                      as username,
      null                      as ttl,
      null                      as key_id,
      null                      as critical_options,
      null                      as extensions,
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
      coalesce(upasso.username_attribute, sshpk.username_attribute, pd.username_attribute)
                                              as username_attribute,
      coalesce(upasso.password_attribute, pd.password_attribute, po.password_attribute)              
                                              as password_attribute,
      pd.domain_attribute                     as domain_attribute,
      sshpk.private_key_attribute             as private_key_attribute,
      sshpk.private_key_passphrase_attribute  as private_key_passphrase_attribute,
      'generic'                               as cred_lib_type, -- used to switch on
      null                                    as additional_valid_principals
      from credential_vault_generic_library library
      join credential_vault_store_client store
        on library.store_id = store.public_id
      left join username_password_override upasso
        on library.public_id = upasso.library_id
      left join ssh_private_key_override sshpk
        on library.public_id = sshpk.library_id
      left join username_password_domain_override pd
        on library.public_id = pd.library_id
      left join password_override po
        on library.public_id = po.library_id
    union
    select library.public_id      as public_id,
      library.store_id            as store_id,
      library.name                as name,
      library.description         as description,
      library.create_time         as create_time,
      library.update_time         as update_time,
      library.version             as version,
      library.vault_path          as vault_path,
      null                        as http_method,
      null                        as http_request_body,
      library.credential_type     as credential_type,
      library.key_type            as key_type,
      library.key_bits            as key_bits,
      library.username            as username,
      library.ttl                 as ttl,
      library.key_id              as key_id,
      library.critical_options    as critical_options,
      library.extensions          as extensions,
      store.project_id            as project_id,
      store.vault_address         as vault_address,
      store.namespace             as namespace,
      store.ca_cert               as ca_cert,
      store.tls_server_name       as tls_server_name,
      store.tls_skip_verify       as tls_skip_verify,
      store.worker_filter         as worker_filter,
      store.ct_token              as ct_token, -- encrypted
      store.token_hmac            as token_hmac,
      store.token_status          as token_status,
      store.token_key_id          as token_key_id,
      store.client_cert           as client_cert,
      store.ct_client_key         as ct_client_key, -- encrypted
      store.client_key_id         as client_key_id,
      null                        as username_attribute,
      null                        as password_attribute,
      null                        as domain_attribute,
      null                        as private_key_attribute,
      null                        as private_key_passphrase_attribute,
      'ssh-signed-cert'           as cred_lib_type, -- used to switch on
      additional_valid_principals as additional_valid_principals
      from credential_vault_ssh_cert_library library
      join credential_vault_store_client store
        on library.store_id = store.public_id
    union
    select library.public_id      as public_id,
      library.store_id            as store_id,
      library.name                as name,
      library.description         as description,
      library.create_time         as create_time,
      library.update_time         as update_time,
      library.version             as version,
      library.vault_path          as vault_path,
      null                        as http_method,
      null                        as http_request_body,
      library.credential_type     as credential_type,
      null                        as key_type,
      null                        as key_bits,
      null                        as username,
      null                        as ttl,
      null                        as key_id,
      null                        as critical_options,
      null                        as extensions,
      store.project_id            as project_id,
      store.vault_address         as vault_address,
      store.namespace             as namespace,
      store.ca_cert               as ca_cert,
      store.tls_server_name       as tls_server_name,
      store.tls_skip_verify       as tls_skip_verify,
      store.worker_filter         as worker_filter,
      store.ct_token              as ct_token, -- encrypted
      store.token_hmac            as token_hmac,
      store.token_status          as token_status,
      store.token_key_id          as token_key_id,
      store.client_cert           as client_cert,
      store.ct_client_key         as ct_client_key, -- encrypted
      store.client_key_id         as client_key_id,
      pd.username_attribute       as username_attribute,
      pd.password_attribute       as password_attribute,
      pd.domain_attribute         as domain_attribute,
      null                        as private_key_attribute,
      null                        as private_key_passphrase_attribute,
      'ldap'                      as cred_lib_type, -- used to switch on
      null                        as additional_valid_principals
      from credential_vault_ldap_library library
      join credential_vault_store_client store
        on library.store_id = store.public_id
      left join username_password_domain_override pd
        on library.public_id = pd.library_id;

  comment on view credential_vault_library_issue_credentials is
    'credential_vault_library_issue_credentials is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
    'This view should only be used when issuing credentials from a Vault credential library. Each row may contain encrypted data. '
    'This view should not be used to retrieve data which will be returned external to boundary.';

  -- Replaces view created in 99/01_credential_vault_library_refactor.up.sql
  drop view credential_vault_generic_library_list_lookup;
  create view credential_vault_generic_library_list_lookup as
  with
    username_password_override (library_id, username_attribute, password_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(password_attribute, wt_to_sentinel('no override'))
      from credential_vault_generic_library_username_password_mapping_ovrd
    ),
    ssh_private_key_override (library_id, username_attribute, private_key_attribute, private_key_passphrase_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(private_key_attribute, wt_to_sentinel('no override')),
        nullif(private_key_passphrase_attribute, wt_to_sentinel('no override'))
      from credential_vault_generic_library_ssh_private_key_mapping_ovrd
    ),
    username_password_domain_override (library_id, username_attribute, password_attribute, domain_attribute) as (
      select library_id,  
        nullif(username_attribute, wt_to_sentinel('no override')),  
        nullif(password_attribute, wt_to_sentinel('no override')),  
        nullif(domain_attribute, wt_to_sentinel('no override'))  
      from credential_vault_generic_library_usern_pass_domain_mapping_ovrd 
    ),
    password_override (library_id, password_attribute) as (
      select library_id,
        nullif(password_attribute, wt_to_sentinel('no override'))
      from credential_vault_generic_library_password_mapping_override
    )
  select library.public_id    as public_id,
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
    coalesce(upasso.username_attribute, sshpk.username_attribute, pd.username_attribute)
                              as username_attribute,
    coalesce(upasso.password_attribute, pd.password_attribute, po.password_attribute)
                              as password_attribute,
    sshpk.private_key_attribute            as private_key_attribute,
    sshpk.private_key_passphrase_attribute as private_key_passphrase_attribute,
    pd.domain_attribute                    as domain_attribute
    from credential_vault_generic_library library
    left join username_password_override upasso
      on library.public_id = upasso.library_id
    left join ssh_private_key_override sshpk
      on library.public_id = sshpk.library_id
    left join username_password_domain_override pd
      on library.public_id = pd.library_id
    left join password_override po
      on library.public_id = po.library_id;
  comment on view credential_vault_generic_library_list_lookup is
    'credential_vault_generic_library_list_lookup is a view where each row contains a credential library and any of library''s credential mapping overrides. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

commit;