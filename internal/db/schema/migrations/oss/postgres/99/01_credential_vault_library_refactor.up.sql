-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- For context, check the README.md in this folder.
begin;
  -- Main table.
  -- Renames the table defined in 10/04_vault_credential.up.sql
  alter table credential_vault_library
    rename to credential_vault_generic_library;

  alter table credential_vault_generic_library
    rename constraint credential_vault_library_pkey to credential_vault_generic_library_pkey;

  alter table credential_vault_generic_library
    rename constraint credential_vault_library_store_id_name_uq to credential_vault_generic_library_store_id_name_uq;

  alter table credential_vault_generic_library
    rename constraint credential_vault_library_store_id_public_id_uq to credential_vault_generic_library_store_id_public_id_uq;

  comment on table credential_vault_generic_library is
    'credential_vault_generic_library is a table where each row is a resource that represents a vault generic credential library. '
    'It is a credential_vault_library subtype and a child table of credential_vault_store.';

  drop trigger insert_deleted_id on credential_vault_generic_library;
  create trigger insert_deleted_id after delete on credential_vault_generic_library
    for each row execute procedure insert_deleted_id('credential_vault_generic_library_deleted');

  insert into oplog_ticket
    (name,                               version)
  values
    ('credential_vault_generic_library', 1)
  on conflict do nothing;
  delete from oplog_ticket where name = 'credential_vault_library';


  -- History table.
  -- Renames the table defined in 71/15_dynamic_credential_history.up.sql
  alter table credential_vault_library_hst
    rename to credential_vault_generic_library_hst;

  alter table credential_vault_generic_library_hst
    rename constraint credential_vault_library_hst_pkey to credential_vault_generic_library_hst_pkey;

  alter table credential_vault_generic_library_hst
    rename constraint credential_vault_library_hst_valid_range_excl to credential_vault_generic_library_hst_valid_range_excl;

  comment on table credential_vault_generic_library_hst is
    'credential_vault_generic_library_hst is a history table where each row contains the values from '
    'a row in the credential_vault_library table during the time range in the valid_range column.';

  -- Updates the function defined in 71/16_recording_dynamic_credential.up.sql
  -- Updated in 100/01_credential_vault_ldap_library.up.sql
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


  -- Deleted table.
  -- Renames table defined in 81/01_deleted_tables_and_triggers.up.sql
  alter table credential_vault_library_deleted
    rename to credential_vault_generic_library_deleted;

  alter table credential_vault_generic_library_deleted
    rename constraint credential_vault_library_deleted_pkey to credential_vault_generic_library_deleted_pkey;

  alter index credential_vault_library_deleted_delete_time_idx
    rename to credential_vault_generic_library_deleted_delete_time_idx;

  comment on table credential_vault_generic_library_deleted is
    'credential_vault_generic_library_deleted holds the ID and delete_time of every deleted Vault credential library. '
    'It is automatically trimmed of records older than 30 days by a job.';


  -- Mapping override base table.
  -- Note that table/constraint/trigger names get very long in the mapping
  -- overrides section, and Postgres limits us to 64-1 chars by default, so we
  -- may have to restrict our naming.
  -- Renames table defined in 22/03_vault_library_map.up.sql
  alter table credential_vault_library_mapping_override
    rename to credential_vault_generic_library_mapping_override;

  alter table credential_vault_generic_library_mapping_override
    rename constraint credential_vault_library_mapping_override_pkey to credential_vault_generic_library_mapping_override_pkey;

  alter table credential_vault_generic_library_mapping_override
    rename constraint credential_vault_library_fkey to credential_vault_generic_library_fkey;

  comment on table credential_vault_generic_library_mapping_override is
    'credential_vault_generic_library_mapping_override is a base table for the vault generic library mapping override type. '
    'Each row is owned by a single vault generic library and maps 1-to-1 to a row in one of the vault generic library mapping override subtype tables.';

  -- These triggers are recreated on each of the tables' specific sections below.
  -- Renames and updates function defined in 22/03_vault_library_map.up.sql
  drop trigger insert_credential_vault_library_mapping_override_subtype on credential_vault_library_username_password_mapping_override;
  drop trigger insert_credential_vault_library_mapping_override_subtype on credential_vault_library_username_password_domain_mapping_ovrd;
  drop trigger insert_credential_vault_library_mapping_override_subtype on credential_vault_library_ssh_private_key_mapping_override;
  drop function insert_credential_vault_library_mapping_override_subtype;
  create function insert_credential_vault_generic_library_mapping_override_subtyp() returns trigger
  as $$
  begin
    insert into credential_vault_generic_library_mapping_override
      (library_id)
    values
      (new.library_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_credential_vault_generic_library_mapping_override_subtyp() is
    'insert_credential_vault_generic_library_mapping_override_subtyp() is a '
    'before insert trigger function that inserts rows from subtype tables into '
    'credential_vault_generic_library_mapping_override. It must be used on all '
    'Vault generic credential library mapping subtype tables.';

  -- These triggers are recreated on each of the tables' specific sections below.
  -- Renames and updates function defined in 22/03_vault_library_map.up.sql
  drop trigger delete_credential_vault_library_mapping_override_subtype on credential_vault_library_username_password_mapping_override;
  drop trigger delete_credential_vault_library_mapping_override_subtype on credential_vault_library_username_password_domain_mapping_ovrd;
  drop trigger delete_credential_vault_library_mapping_override_subtype on credential_vault_library_ssh_private_key_mapping_override;
  drop function delete_credential_vault_library_mapping_override_subtype;
  create function delete_credential_vault_generic_library_mapping_override_subtyp() returns trigger
  as $$
  begin
    delete from credential_vault_generic_library_mapping_override
    where library_id = old.library_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_credential_vault_generic_library_mapping_override_subtyp() is
    'delete_credential_vault_generic_library_mapping_override_subtyp() is a '
    'before insert trigger function that deletes rows from '
    'credential_vault_generic_library_mapping_override when they''re deleted '
    'on the subtype tables. It must be used on all Vault generic credential '
    'library mapping subtype tables.';


  -- Mapping override: SSH PK table.
  -- Renames table defined in 39/02_vault_ssh_private_key_override.up.sql
  alter table credential_vault_library_ssh_private_key_mapping_override
    rename to credential_vault_generic_library_ssh_private_key_mapping_ovrd;

  alter table credential_vault_generic_library_ssh_private_key_mapping_ovrd
    rename constraint credential_vault_library_ssh_private_key_mapping_override_pkey to credential_vault_generic_library_ssh_priv_key_mapping_ovrd_pkey;

  alter table credential_vault_generic_library_ssh_private_key_mapping_ovrd
    rename constraint credential_vault_library_mapping_override_fkey to credential_vault_generic_library_mapping_override_fkey;

  alter table credential_vault_generic_library_ssh_private_key_mapping_ovrd
    rename constraint credential_vault_library_fkey to credential_vault_generic_library_fkey;

  comment on table credential_vault_generic_library_ssh_private_key_mapping_ovrd is
    'credential_vault_generic_library_ssh_private_key_mapping_ovrd is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a ssh private key credential type '
    'for a vault generic credential library.';

  create trigger insert_credential_vault_generic_library_mapping_override_subtyp before insert on credential_vault_generic_library_ssh_private_key_mapping_ovrd
    for each row execute procedure insert_credential_vault_generic_library_mapping_override_subtyp();

  create trigger delete_credential_vault_generic_library_mapping_override_subtyp after delete on credential_vault_generic_library_ssh_private_key_mapping_ovrd
    for each row execute procedure delete_credential_vault_generic_library_mapping_override_subtyp();


  -- Mapping override: Username & Password table.
  -- Renames table in 36/01_vault_library_map_username_password.up.sql
  alter table credential_vault_library_username_password_mapping_override
    rename to credential_vault_generic_library_username_password_mapping_ovrd;

  alter table credential_vault_generic_library_username_password_mapping_ovrd
    rename constraint credential_vault_library_user_password_mapping_override_pkey to credential_vault_generic_library_usern_pass_mapping_ovrd_pkey;

  alter table credential_vault_generic_library_username_password_mapping_ovrd
    rename constraint credential_vault_library_fkey to credential_vault_generic_library_fkey;

  alter table credential_vault_generic_library_username_password_mapping_ovrd
    rename constraint credential_vault_library_mapping_override_fkey to credential_vault_generic_library_mapping_override_fkey;

  comment on table credential_vault_generic_library_username_password_mapping_ovrd is
    'credential_vault_generic_library_username_password_mapping_ovrd is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a username password credential type '
    'for a vault generic credential library.';

  create trigger insert_credential_vault_generic_library_mapping_override_subtyp before insert on credential_vault_generic_library_username_password_mapping_ovrd
    for each row execute procedure insert_credential_vault_generic_library_mapping_override_subtyp();

  create trigger delete_credential_vault_generic_library_mapping_override_subtyp after delete on credential_vault_generic_library_username_password_mapping_ovrd
    for each row execute procedure delete_credential_vault_generic_library_mapping_override_subtyp();


  -- Mapping override: Username, Password & Domain table.
  -- Renames table defined in 98/02_username_password_domain_vault.up.sql
  alter table credential_vault_library_username_password_domain_mapping_ovrd
    rename to credential_vault_generic_library_usern_pass_domain_mapping_ovrd;

  alter table credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    rename constraint credential_vault_library_username_password_domain_mapping__pkey to credential_vault_generic_library_upd_mapping_ovrd_pkey;

  alter table credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    rename constraint credential_vault_library_fkey to credential_vault_generic_library_fkey;

  alter table credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    rename constraint credential_vault_library_mapping_override_fkey to credential_vault_generic_library_mapping_override_fkey;

  comment on table credential_vault_generic_library_usern_pass_domain_mapping_ovrd is
    'credential_vault_generic_library_usern_pass_domain_mapping_ovrd is a table '
    'where each row represents a mapping that overrides the default mapping '
    'from a generic vault secret to a user password domain credential type '
    'for a vault generic credential library.';

  create trigger insert_credential_vault_generic_library_mapping_override_subtyp before insert on credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    for each row execute procedure insert_credential_vault_generic_library_mapping_override_subtyp();

  create trigger delete_credential_vault_generic_library_mapping_override_subtyp after delete on credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    for each row execute procedure delete_credential_vault_generic_library_mapping_override_subtyp();


  -- Views. Postgres already automatically updated them to reference the renamed
  -- tables, however these should still be explictly in the migration.
  --   > whx_credential_dimension_source
  --   > credential_vault_library_issue_credentials
  --   > credential_vault_library_list_lookup: Renamed to credential_vault_generic_library_list_lookup.
  --   > credential_vault_library_hst_aggregate: Renamed to credential_vault_generic_library_hst_aggregate.

  -- Replaces view defined in 98/04_rdp_targets.up.sql
  -- Replaced in 100/01_credential_vault_ldap_library.up.sql
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
    final as (
          select s.public_id                                              as session_id,
                 scd.credential_purpose                                   as credential_purpose,
                 cl.public_id                                             as credential_library_id,
                 coalesce(vcl.type,              vsccl.type)              as credential_library_type,
                 coalesce(vcl.name,              vsccl.name)              as credential_library_name,
                 coalesce(vcl.description,       vsccl.description)       as credential_library_description,
                 coalesce(vcl.vault_path,        vsccl.vault_path)        as credential_library_vault_path,
                 coalesce(vcl.http_method,       vsccl.http_method)       as credential_library_vault_http_method,
                 coalesce(vcl.http_request_body, vsccl.http_request_body) as credential_library_vault_http_request_body,
                 coalesce(vcl.username,          vsccl.username)          as credential_library_username,
                 coalesce(vcl.key_type_and_bits, vsccl.key_type_and_bits) as credential_library_key_type_and_bits,
                 cs.public_id                                             as credential_store_id,
                 case
                   when vcs is null then 'None'
                   else 'vault credential store'
                 end                                                      as credential_store_type,
                 coalesce(vcs.name,              'None')                  as credential_store_name,
                 coalesce(vcs.description,       'None')                  as credential_store_description,
                 coalesce(vcs.namespace,         'None')                  as credential_store_vault_namespace,
                 coalesce(vcs.vault_address,     'None')                  as credential_store_vault_address,
                 t.public_id                                              as target_id,
                 case
                   when tt.type = 'tcp' then 'tcp target'
                   when tt.type = 'ssh' then 'ssh target'
                   when tt.type = 'rdp' then 'rdp target'
                   else 'Unknown'
                 end                                                      as target_type,
                 coalesce(tt.name,               'None')                  as target_name,
                 coalesce(tt.description,        'None')                  as target_description,
                 coalesce(tt.default_port,       0)                       as target_default_port_number,
                 tt.session_max_seconds                                   as target_session_max_seconds,
                 tt.session_connection_limit                              as target_session_connection_limit,
                 p.public_id                                              as project_id,
                 coalesce(p.name,                'None')                  as project_name,
                 coalesce(p.description,         'None')                  as project_description,
                 o.public_id                                              as organization_id,
                 coalesce(o.name,                'None')                  as organization_name,
                 coalesce(o.description,         'None')                  as organization_description
            from session_credential_dynamic as scd
            join session                as s     on scd.session_id = s.public_id
            join credential_library     as cl    on scd.library_id = cl.public_id
            join credential_store       as cs    on cl.store_id    = cs.public_id
            join target                 as t     on s.target_id    = t.public_id
            join iam_scope              as p     on p.public_id    = t.project_id and p.type = 'project'
            join iam_scope              as o     on p.parent_id    = o.public_id  and o.type = 'org'
       left join vault_generic_library  as vcl   on cl.public_id   = vcl.public_id
       left join vault_ssh_cert_library as vsccl on cl.public_id   = vsccl.public_id
       left join credential_vault_store as vcs   on cs.public_id   = vcs.public_id
       left join target_all_subtypes    as tt    on t.public_id    = tt.public_id
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

  -- Replaces view defined in 98/02_username_password_domain_vault.up.sql
  -- Replaced in 100/01_credential_vault_ldap_library.up.sql
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
      on library.store_id = store.public_id;
  comment on view credential_vault_library_issue_credentials is
    'credential_vault_library_issue_credentials is a view where each row contains a credential library and the credential library''s data needed to connect to Vault. '
    'This view should only be used when issuing credentials from a Vault credential library. Each row may contain encrypted data. '
    'This view should not be used to retrieve data which will be returned external to boundary.';

  -- Replaces and renames view defined in 98/02_username_password_domain_vault.up.sql.
  -- Replaced in 101/02_credential_vault_password_library.up.sql
  alter view credential_vault_library_list_lookup
    rename to credential_vault_generic_library_list_lookup;
  drop view credential_vault_generic_library_list_lookup;
  create view credential_vault_generic_library_list_lookup as
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
    coalesce(upasso.username_attribute, sshpk.username_attribute, pd.username_attribute)
                              as username_attribute,
    coalesce(upasso.password_attribute, pd.password_attribute)
                              as password_attribute,
    sshpk.private_key_attribute            as private_key_attribute,
    sshpk.private_key_passphrase_attribute as private_key_passphrase_attribute,
    pd.domain_attribute                    as domain_attribute
    from credential_vault_generic_library library
    left join password_override upasso
      on library.public_id = upasso.library_id
    left join ssh_private_key_override sshpk
      on library.public_id = sshpk.library_id
    left join password_domain_override pd
      on library.public_id = pd.library_id;
  comment on view credential_vault_generic_library_list_lookup is
    'credential_vault_generic_library_list_lookup is a view where each row contains a Vault generic credential library and any of library''s credential mapping overrides. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

  -- Replaces and renames view defined in 71/17_credential_history_views.up.sql.
  alter view credential_vault_library_hst_aggregate
    rename to credential_vault_generic_library_hst_aggregate;
  drop view credential_vault_generic_library_hst_aggregate;
  create view credential_vault_generic_library_hst_aggregate as
  select
    rdc.recording_id,
    vl.public_id,
    vl.name,
    vl.description,
    vl.vault_path,
    vl.http_method,
    vl.http_request_body,
    vl.credential_type,
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
  from credential_vault_generic_library_hst as vl
     left join recording_dynamic_credential as rdc on vl.history_id = rdc.credential_library_hst_id
     join credential_vault_store_hst as vsh on rdc.credential_vault_store_hst_id = vsh.history_id
  group by vl.history_id, rdc.recording_id, vsh.history_id;
  comment on view credential_vault_generic_library_hst_aggregate is
    'credential_vault_generic_library_hst_aggregate contains Vault generic credential library history data along with its store and purpose data.';


  -- Renaming is complete. We can now redefine credential_vault_library and
  -- rewire all the Vault subtype tables into this redefined table.

    -- credential_vault_store doesn't have a unique constraint on (project_id,
    -- public_id) fields. We'll need this to attach a FK to them later. There
    -- should be no side-effects from this given that:
    --   > public_id is a PK (already globally unique) and,
    --   > credential_vault_store is a subtype table of credential_store, which
    --     does have a (project_id, public_id) uniqueness constraint.
    alter table credential_vault_store
      add constraint credential_vault_store_project_id_public_id_uq
        unique(project_id, public_id);

  -- This statement defines the basic fields and pulls all the data from
  -- credential_library. We can do this as a blanket select * statement because
  -- only Vault-subtype credential libraries exist at this point.
  --
  -- We want to insert the data before any constraints are set because
  -- credential_library has had a few revisions and while we have also updated
  -- the data alongside those table revisions, success on an insert with
  -- historical data isn't guaranteed. Additionally, we also want to do this
  -- before any triggers are put in place.
  create table credential_vault_library as
    select * from credential_library;

  alter table credential_vault_library
    add primary key (public_id),
    alter column store_id set not null,
    alter column credential_type set not null,
    alter column credential_type set default 'unspecified',
    add constraint credential_type_enm_fkey
      foreign key (credential_type)
        references credential_type_enm (name)
        on delete restrict
        on update cascade,
    alter column project_id set not null,
    alter column create_time set not null,
    alter column update_time set not null,
    add constraint credential_library_fkey
      foreign key (public_id, store_id, credential_type, project_id)
        references credential_library (public_id, store_id, credential_type, project_id)
        on delete cascade
        on update cascade,
    add constraint credential_vault_store_fkey
      foreign key (project_id, store_id)
        references credential_vault_store (project_id, public_id)
        on delete cascade
        on update cascade,
    add constraint credential_vault_library_project_id_public_id_uq
      unique(project_id, public_id),
    add constraint credential_vault_library_project_store_public_ids_credtype_uq
      unique(project_id, store_id, public_id, credential_type);
  comment on table credential_vault_library is
  'credential_vault_library is a base table for Vault credential library '
  'subtypes and a child table of credential_vault_store. Each row maps 1-to-1 '
  'to a row in one of the Vault credential library subtype tables.';

  create trigger immutable_columns before update on credential_vault_library
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id', 'credential_type');
  create trigger insert_credential_library_subtype before insert on credential_vault_library
    for each row execute procedure insert_credential_library_subtype();
  create trigger delete_credential_library_subtype after delete on credential_vault_library
    for each row execute procedure delete_credential_library_subtype();
  create trigger update_credential_library_table_update_time before update on credential_vault_library
    for each row execute procedure update_credential_library_table_update_time();

  create index credential_vault_library_create_time_public_id_idx
    on credential_vault_library (create_time desc, public_id desc);
  create index credential_vault_library_update_time_public_id_idx
    on credential_vault_library (update_time desc, public_id desc);

  create or replace function insert_credential_vault_library_subtype() returns trigger
  as $$
  begin
    select project_id into new.project_id
      from credential_store
     where credential_store.public_id = new.store_id;

    insert into credential_vault_library
      (public_id, store_id, project_id, credential_type, create_time)
    values
      (new.public_id, new.store_id, new.project_id, new.credential_type, new.create_time);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_credential_vault_library_subtype() is
    'insert_credential_vault_library_subtype is a before insert trigger '
    'function that inserts rows from subtype tables into '
    'credential_vault_library. It must be used on all Vault credential library '
    'subtype tables.';

  create function delete_credential_vault_library_subtype() returns trigger
  as $$
  begin
    delete from credential_vault_library
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_credential_vault_library_subtype() is
    'delete_credential_vault_library_subtype is an after delete trigger '
    'function that deletes rows from credential_vault_library when they''re '
    'deleted on the subtype tables. It must be used on all Vault credential '
    'library subtype tables.';

  create function update_credential_vault_library_table_update_time() returns trigger
  as $$
  begin
    update credential_vault_library set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_credential_vault_library_table_update_time() is
    'update_credential_vault_library_table_update_time is a before update '
    'trigger function that updates the update_time column on '
    'credential_vault_library. It must be used on all Vault credential library '
    'subtype tables.';


  -- We still have some entities on the Vault subtype tables that reference
  -- credential_library when they should now reference credential_vault_library.
  alter table credential_vault_generic_library
    drop constraint credential_library_fkey,
    add constraint credential_vault_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
        references credential_vault_library (project_id, store_id, public_id, credential_type)
        on delete cascade
        on update cascade;

  -- Updates table defined in 63/01_credential_vault_ssh_cert_library.up.sql
  alter table credential_vault_ssh_cert_library
    drop constraint credential_library_fkey,
    add constraint credential_vault_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
        references credential_vault_library (project_id, store_id, public_id, credential_type)
        on delete cascade
        on update cascade;

  drop trigger insert_credential_library_subtype on credential_vault_generic_library;
  create trigger insert_credential_vault_library_subtype before insert on credential_vault_generic_library
    for each row execute procedure insert_credential_vault_library_subtype();

  drop trigger delete_credential_library_subtype on credential_vault_generic_library;
  create trigger delete_credential_vault_library_subtype after delete on credential_vault_generic_library
    for each row execute procedure delete_credential_vault_library_subtype();

  drop trigger update_credential_library_table_update_time on credential_vault_generic_library;
  create trigger update_credential_vault_library_table_update_time before update on credential_vault_generic_library
    for each row execute procedure update_credential_vault_library_table_update_time();

  drop trigger insert_credential_library_subtype on credential_vault_ssh_cert_library;
  create trigger insert_credential_vault_library_subtype before insert on credential_vault_ssh_cert_library
    for each row execute procedure insert_credential_vault_library_subtype();

  drop trigger delete_credential_library_subtype on credential_vault_ssh_cert_library;
  create trigger delete_credential_vault_library_subtype after delete on credential_vault_ssh_cert_library
    for each row execute procedure delete_credential_vault_library_subtype();

  drop trigger update_credential_library_table_update_time on credential_vault_ssh_cert_library;
  create trigger update_credential_vault_library_table_update_time before update on credential_vault_ssh_cert_library
    for each row execute procedure update_credential_vault_library_table_update_time();

  -- Finally, we can correct the restriction in credential_vault_credential.
  -- credential_vault_library is now a superset of
  -- credential_vault_generic_library, so this shouldn't have side-effects.
  -- Updates the table defined in 10/04_vault_credential.up.sql
  alter table credential_vault_credential
    drop constraint credential_vault_library_fkey,
    add constraint credential_vault_library_fkey
      foreign key (library_id)
        references credential_vault_library (public_id)
        on delete set null
        on update cascade;
commit;
