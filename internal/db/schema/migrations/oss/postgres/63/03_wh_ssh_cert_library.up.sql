-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  alter table wh_credential_dimension
    add column credential_library_username text,
    add column credential_library_key_type_and_bits text
  ;

  update wh_credential_dimension set
    credential_library_username = 'Not Applicable',
    credential_library_key_type_and_bits = 'Not Applicable';

  update wh_credential_dimension set
    credential_library_vault_http_request_body = 'Not Applicable'
  where
    credential_library_vault_http_method = 'GET'
  and
    credential_library_vault_http_request_body = 'None';


  alter table wh_credential_dimension
    alter column credential_library_username type wh_dim_text,
    alter column credential_library_key_type_and_bits type wh_dim_text
  ;

  update wh_credential_dimension set
    credential_library_type = 'vault generic credential library'
  where
    credential_library_type = 'vault credential library';

  -- The whx_credential_dimension_source view shows the current values in the
  -- operational tables of the credential dimension.
  -- Replaces whx_credential_dimension_source defined in 44/03_targets.up.sql
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
        from credential_vault_library as vcl
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
                 'tcp target'                                             as target_type,
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
                 coalesce(o.description,         'None')                 as organization_description
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
       left join target_tcp             as tt    on t.public_id    = tt.public_id
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

  -- Replaces view in 16/02_wh_credential_dimension.up.sql
  drop view whx_credential_dimension_target;
  create view whx_credential_dimension_target as
  select key,
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
    from wh_credential_dimension
   where current_row_indicator = 'Current'
  ;

  -- Replaces function in 16/03_wh_credential_dimension.up.sql
  drop function wh_upsert_credential_dimension;
  create function wh_upsert_credential_dimension(p_session_id wt_public_id, p_library_id wt_public_id, p_credential_purpose wh_dim_text) returns wh_dim_key
  as $$
  declare
    src     whx_credential_dimension_target%rowtype;
    target  whx_credential_dimension_target%rowtype;
    new_row wh_credential_dimension%rowtype;
    t_id    wt_public_id;
  begin
    select s.target_id into strict t_id
      from session as s
     where s.public_id = p_session_id;

    select * into target
      from whx_credential_dimension_target as t
     where t.credential_library_id = p_library_id
       and t.target_id             = t_id
       and t.credential_purpose    = p_credential_purpose;

    select
      target.key,                    t.credential_purpose,
      t.credential_library_id,       t.credential_library_type,     t.credential_library_name,     t.credential_library_description, t.credential_library_vault_path,    t.credential_library_vault_http_method, t.credential_library_vault_http_request_body,
      t.credential_library_username, t.credential_library_key_type_and_bits,
      t.credential_store_id,         t.credential_store_type,       t.credential_store_name,       t.credential_store_description,   t.credential_store_vault_namespace, t.credential_store_vault_address,
      t.target_id,                   t.target_type,                 t.target_name,                 t.target_description,             t.target_default_port_number,       t.target_session_max_seconds,           t.target_session_connection_limit,
      t.project_id,                  t.project_name,                t.project_description,
      t.organization_id,             t.organization_name,           t.organization_description
      into src
      from whx_credential_dimension_source as t
     where t.credential_library_id = p_library_id
       and t.session_id            = p_session_id
       and t.target_id             = t_id
       and t.credential_purpose    = p_credential_purpose;

    if src is distinct from target then
      update wh_credential_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where credential_library_id = p_library_id
         and target_id             = t_id
         and credential_purpose    = p_credential_purpose
         and current_row_indicator = 'Current';

      insert into wh_credential_dimension (
             credential_purpose,
             credential_library_id,       credential_library_type,     credential_library_name,     credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
             credential_library_username, credential_library_key_type_and_bits,
             credential_store_id,         credential_store_type,       credential_store_name,       credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
             target_id,                   target_type,                 target_name,                 target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
             project_id,                  project_name,                project_description,
             organization_id,             organization_name,           organization_description,
             current_row_indicator,       row_effective_time,          row_expiration_time
      )
      select credential_purpose,
             credential_library_id,       credential_library_type,     credential_library_name,     credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
             credential_library_username, credential_library_key_type_and_bits,
             credential_store_id,         credential_store_type,       credential_store_name,       credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
             target_id,                   target_type,                 target_name,                 target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
             project_id,                  project_name,                project_description,
             organization_id,             organization_name,           organization_description,
             'Current',                   current_timestamp,           'infinity'::timestamptz
        from whx_credential_dimension_source
       where credential_library_id = p_library_id
         and session_id            = p_session_id
         and target_id             = t_id
         and credential_purpose    = p_credential_purpose
      returning * into new_row;

      return new_row.key;
    end if;

    return target.key;
  end
  $$ language plpgsql;
commit;
