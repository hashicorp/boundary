-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create table credential_vault_ldap_library (
    public_id wt_public_id primary key,
    project_id wt_public_id not null,
    store_id wt_public_id not null
      constraint credential_vault_store_fkey
      references credential_vault_store (public_id)
      on delete cascade
      on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    vault_path text not null
      constraint vault_path_must_not_be_empty
        check(length(trim(vault_path)) > 0)
      constraint vault_path_must_have_staticcred_or_creds
        check(vault_path ~ '^.+\/(static-cred|creds)\/(?:[^\/\\\s]+\/)*[^\/\\\s]+$'),
    credential_type text not null
      constraint credential_type_enm_fkey
        references credential_type_enm (name)
        on delete restrict
        on update cascade,
    constraint credential_vault_ldap_library_store_id_public_id_uq
     unique(store_id, public_id),
    constraint credential_vault_ldap_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_vault_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
        references credential_vault_library (project_id, store_id, public_id, credential_type)
        on delete cascade
        on update cascade
  );

  comment on table credential_vault_ldap_library is
    'credential_vault_ldap_library is a credential library that issues credentials from a vault ldap secret backend.';

  create trigger insert_credential_vault_library_subtype before insert on credential_vault_ldap_library
    for each row execute procedure insert_credential_vault_library_subtype();

  create trigger update_credential_vault_library_table_update_time before update on credential_vault_ldap_library
    for each row execute procedure update_credential_vault_library_table_update_time();

  create trigger immutable_columns before update on credential_vault_ldap_library
    for each row execute procedure immutable_columns('public_id', 'store_id', 'project_id', 'credential_type', 'create_time');

  create trigger delete_credential_vault_library_subtype after delete on credential_vault_ldap_library
    for each row execute procedure delete_credential_vault_library_subtype();

  create trigger update_version_column after update on credential_vault_ldap_library
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_vault_ldap_library
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_ldap_library
    for each row execute procedure default_create_time();

  create trigger before_insert_credential_vault_library before insert on credential_vault_ldap_library
    for each row execute procedure before_insert_credential_vault_library();

  create function default_vault_ldap_credential_type() returns trigger
    as $$
    begin
      if new.credential_type is distinct from 'username_password_domain' then
        new.credential_type = 'username_password_domain';
      end if;
      return new;
    end;
    $$ language plpgsql;
    comment on function default_vault_ldap_credential_type is
      'default_vault_ldap_credential_type ensures the credential_type is set to username_password_domain';

  create trigger default_vault_ldap_credential_type before insert on credential_vault_ldap_library
    for each row execute procedure default_vault_ldap_credential_type();

  -- Replaces view from 99/01_credential_vault_library_refactor.up.sql
  drop view credential_vault_library_issue_credentials;
  create view credential_vault_library_issue_credentials as
  with
    password_override (library_id, username_attribute, password_attribute) as (
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
    password_domain_override (library_id, username_attribute, password_attribute, domain_attribute) as (
      select library_id,
        nullif(username_attribute, wt_to_sentinel('no override')),
        nullif(password_attribute, wt_to_sentinel('no override')),
        nullif(domain_attribute, wt_to_sentinel('no override'))
      from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
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
    coalesce(upasso.password_attribute, pd.password_attribute)
                                            as password_attribute,
    pd.domain_attribute                     as domain_attribute,
    sshpk.private_key_attribute             as private_key_attribute,
    sshpk.private_key_passphrase_attribute  as private_key_passphrase_attribute,
    'generic'                               as cred_lib_type, -- used to switch on
    null                                    as additional_valid_principals
    from credential_vault_generic_library library
    join credential_vault_store_client store
      on library.store_id = store.public_id
    left join password_override upasso
      on library.public_id = upasso.library_id
    left join ssh_private_key_override sshpk
      on library.public_id = sshpk.library_id
    left join password_domain_override pd
      on library.public_id = pd.library_id
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
    left join password_domain_override pd
      on library.public_id = pd.library_id;

  comment on view credential_vault_library_issue_credentials is
    'credential_vault_library_issue_credentials is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
    'This view should only be used when issuing credentials from a Vault credential library. Each row may contain encrypted data. '
    'This view should not be used to retrieve data which will be returned external to boundary.';

insert into oplog_ticket (name, version)
values
    ('credential_vault_ldap_library', 1);

commit;
