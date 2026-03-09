-- Copyright IBM Corp. 2020, 2025
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
  -- Replaced in 101/02_credential_vault_password_library.up.sql
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

  create table credential_vault_ldap_library_hst (
    public_id wt_public_id not null,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    name wt_name,
    description wt_description,
    vault_path text not null,
    credential_type text not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_library_history_base_fkey
        references credential_library_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_vault_ldap_library_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_vault_ldap_library_hst is
    'credential_vault_ldap_library_hst is a history table where each row contains values from a row '
    'in the credential_vault_ldap_library table during the time range in the valid_range column';

  create trigger insert_credential_library_history_subtype before insert on credential_vault_ldap_library_hst
    for each row execute function insert_credential_library_history_subtype();

  create trigger delete_credential_library_history_subtype after delete on credential_vault_ldap_library_hst
    for each row execute function delete_credential_library_history_subtype();

  create trigger hst_on_insert after insert on credential_vault_ldap_library
    for each row execute function hst_on_insert();

  create trigger hst_on_update after update on credential_vault_ldap_library
    for each row execute function hst_on_update();

  create trigger hst_on_delete after delete on credential_vault_ldap_library
    for each row execute function hst_on_delete();

  create view credential_vault_ldap_library_hst_aggregate as
  select
    rdc.recording_id,
    vll.public_id,
    vll.name,
    vll.description,
    vll.vault_path,
    vll.credential_type,
    vsh.public_id as store_public_id,
    vsh.project_id as store_project_id,
    vsh.name as store_name,
    vsh.description as store_description,
    vsh.vault_address as store_vault_address,
    vsh.namespace as store_namespace,
    vsh.tls_server_name as store_tls_server_name,
    vsh.tls_skip_verify as store_tls_skip_verify,
    vsh.worker_filter as store_worker_filter,
    string_agg(distinct rdc.credential_purpose, '|') as purposes
  from credential_vault_ldap_library_hst as vll
     left join recording_dynamic_credential as rdc on vll.history_id = rdc.credential_library_hst_id
     join credential_vault_store_hst as vsh on rdc.credential_vault_store_hst_id = vsh.history_id
  group by vll.history_id, rdc.recording_id, vsh.history_id;
  comment on view credential_vault_ldap_library_hst_aggregate is
    'credential_vault_ldap_library_hst_aggregate contains the vault ldap library history data along with its store and purpose data.';

  create table credential_vault_ldap_library_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table credential_vault_ldap_library_deleted is
    'credential_vault_ldap_library_deleted holds the ID and delete_time '
    'of every deleted vault ldap credential'
    'It is automatically trimmed of records older than 30 days by a job.';

  create index credential_vault_ldap_library_deleted_delete_time_idx on credential_vault_ldap_library_deleted (delete_time);

  create trigger insert_deleted_id after delete on credential_vault_ldap_library
    for each row execute function insert_deleted_id('credential_vault_ldap_library_deleted');

  -- Replaces the function in 99/01_credential_vault_library_refactor.up.sql
  drop trigger insert_recording_dynamic_credentials on recording_session;
  drop function insert_recording_dynamic_credentials();
  create function insert_recording_dynamic_credentials() returns trigger
  as $$
  begin
    with
    session_recording(session_id, recording_id) as (
      select session_id, public_id
        from recording_session
       where session_id = new.session_id
    ),
    session_dynamic_creds(library_id, purpose, recording_id) as (
      select library_id, credential_purpose, recording_id
        from session_credential_dynamic
        join session_recording using (session_id)
    ),
    library_history(public_id, store_id, library_hst_id, valid_range) as (
      select public_id, store_id, history_id, valid_range
        from credential_vault_generic_library_hst
       union
      select public_id, store_id, history_id, valid_range
        from credential_vault_ssh_cert_library_hst
       union
      select public_id, store_id, history_id, valid_range
        from credential_vault_ldap_library_hst
    ),
    final(recording_id, library_id, store_id, library_hst_id, store_hst_id, cred_purpose) as (
      select sdc.recording_id, lib.public_id, lib.store_id, lib.library_hst_id, store_hst.history_id, sdc.purpose
        from library_history as lib
        join credential_vault_store_hst as store_hst on lib.store_id = store_hst.public_id
         and store_hst.valid_range @> current_timestamp
        join session_dynamic_creds as sdc on lib.public_id = sdc.library_id
       where lib.public_id in (select library_id from session_dynamic_creds)
         and lib.valid_range @> current_timestamp
    )
    insert into recording_dynamic_credential
          (recording_id, credential_vault_store_hst_id, credential_library_hst_id, credential_purpose)
    select recording_id, store_hst_id,                  library_hst_id,            cred_purpose
      from final;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_recording_dynamic_credentials is
    'insert_recording_dynamic_credentials is an after insert trigger for the recording_session table.';

  create trigger insert_recording_dynamic_credentials after insert on recording_session
    for each row execute procedure insert_recording_dynamic_credentials();

  -- Replaces view defined in 99/01_credential_vault_library_refactor.up.sql
  drop view whx_credential_dimension_source;
  create view whx_credential_dimension_source as
    with vault_generic_library as (
      select vcl.public_id                                        as public_id,
             'vault generic credential library'                   as type,
             coalesce(vcl.name,        'None')                    as name,
             coalesce(vcl.description, 'None')                    as description,
             vcl.vault_path                                       as vault_path,
             vcl.http_method                                      as http_method,
             case
               when vcl.http_method = 'GET' then 'Not Applicable'
               else coalesce(vcl.http_request_body::text, 'None')
             end                                                  as http_request_body,
             'Not Applicable'                                     as username,
             'Not Applicable'                                     as key_type_and_bits
        from credential_vault_generic_library as vcl
    ),
    vault_ssh_cert_library as (
      select vsccl.public_id                                      as public_id,
             'vault ssh certificate credential library'           as type,
             coalesce(vsccl.name,        'None')                  as name,
             coalesce(vsccl.description, 'None')                  as description,
             vsccl.vault_path                                     as vault_path,
             'Not Applicable'                                     as http_method,
             'Not Applicable'                                     as http_request_body,
             vsccl.username                                       as username,
             case
               when vsccl.key_type = 'ed25519' then vsccl.key_type
               else vsccl.key_type || '-' || vsccl.key_bits::text
             end                                                  as key_type_and_bits
        from credential_vault_ssh_cert_library as vsccl
    ),
    vault_ldap_library as (
      select vldapcl.public_id                                    as public_id,
             'vault ldap credential library'                      as type,
             coalesce(vldapcl.name,        'None')                as name,
             coalesce(vldapcl.description, 'None')                as description,
             vldapcl.vault_path                                   as vault_path,
             'Not Applicable'                                     as http_method,
             'Not Applicable'                                     as http_request_body,
             'Not Applicable'                                     as username,
             'Not Applicable'                                     as key_type_and_bits
        from credential_vault_ldap_library as vldapcl
    ),
    final as (
          select s.public_id                                                                         as session_id,
                 scd.credential_purpose                                                              as credential_purpose,
                 cl.public_id                                                                        as credential_library_id,
                 coalesce(vcl.type,              vsccl.type,              vldapcl.type)              as credential_library_type,
                 coalesce(vcl.name,              vsccl.name,              vldapcl.name)              as credential_library_name,
                 coalesce(vcl.description,       vsccl.description,       vldapcl.description)       as credential_library_description,
                 coalesce(vcl.vault_path,        vsccl.vault_path,        vldapcl.vault_path)        as credential_library_vault_path,
                 coalesce(vcl.http_method,       vsccl.http_method,       vldapcl.http_method)       as credential_library_vault_http_method,
                 coalesce(vcl.http_request_body, vsccl.http_request_body, vldapcl.http_request_body) as credential_library_vault_http_request_body,
                 coalesce(vcl.username,          vsccl.username,          vldapcl.username)          as credential_library_username,
                 coalesce(vcl.key_type_and_bits, vsccl.key_type_and_bits, vldapcl.key_type_and_bits) as credential_library_key_type_and_bits,
                 cs.public_id                                                                        as credential_store_id,
                 case
                   when vcs is null then 'None'
                   else 'vault credential store'
                 end                                                                                 as credential_store_type,
                 coalesce(vcs.name,              'None')                                             as credential_store_name,
                 coalesce(vcs.description,       'None')                                             as credential_store_description,
                 coalesce(vcs.namespace,         'None')                                             as credential_store_vault_namespace,
                 coalesce(vcs.vault_address,     'None')                                             as credential_store_vault_address,
                 t.public_id                                                                         as target_id,
                 case
                   when tt.type = 'tcp' then 'tcp target'
                   when tt.type = 'ssh' then 'ssh target'
                   when tt.type = 'rdp' then 'rdp target'
                   else 'Unknown'
                 end                                                                                 as target_type,
                 coalesce(tt.name,               'None')                                             as target_name,
                 coalesce(tt.description,        'None')                                             as target_description,
                 coalesce(tt.default_port,       0)                                                  as target_default_port_number,
                 tt.session_max_seconds                                                              as target_session_max_seconds,
                 tt.session_connection_limit                                                         as target_session_connection_limit,
                 p.public_id                                                                         as project_id,
                 coalesce(p.name,                'None')                                             as project_name,
                 coalesce(p.description,         'None')                                             as project_description,
                 o.public_id                                                                         as organization_id,
                 coalesce(o.name,                'None')                                             as organization_name,
                 coalesce(o.description,         'None')                                             as organization_description
            from session_credential_dynamic as scd
            join session                    as s       on scd.session_id = s.public_id
            join credential_library         as cl      on scd.library_id = cl.public_id
            join credential_store           as cs      on cl.store_id    = cs.public_id
            join target                     as t       on s.target_id    = t.public_id
            join iam_scope                  as p       on p.public_id    = t.project_id and p.type = 'project'
            join iam_scope                  as o       on p.parent_id    = o.public_id  and o.type = 'org'
       left join vault_generic_library      as vcl     on cl.public_id   = vcl.public_id
       left join vault_ssh_cert_library     as vsccl   on cl.public_id   = vsccl.public_id
       left join vault_ldap_library         as vldapcl on cl.public_id   = vldapcl.public_id
       left join credential_vault_store     as vcs     on cs.public_id   = vcs.public_id
       left join target_all_subtypes        as tt      on t.public_id    = tt.public_id
    )
    select session_id,
           credential_purpose,
           credential_library_id,
           credential_library_type,
           credential_library_name,
           credential_library_description,
           credential_library_vault_path,
           credential_library_vault_http_method,
           credential_library_vault_http_request_body,
           credential_library_username,
           credential_library_key_type_and_bits,
           credential_store_id,
           credential_store_type,
           credential_store_name,
           credential_store_description,
           credential_store_vault_namespace,
           credential_store_vault_address,
           target_id,
           target_type,
           target_name,
           target_description,
           target_default_port_number,
           target_session_max_seconds,
           target_session_connection_limit,
           project_id,
           project_name,
           project_description,
           organization_id,
           organization_name,
           organization_description
      from final;

commit;
