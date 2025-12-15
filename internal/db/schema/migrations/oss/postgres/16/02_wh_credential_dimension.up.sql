-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- The whx_credential_dimension_source and whx_credential_dimension_target views are used
  -- by an insert trigger to determine if the current row for the dimension has
  -- changed and a new one needs to be inserted. The first column in the target view
  -- must be the current warehouse id and all remaining columns must match the columns
  -- in the source view.

  -- The whx_credential_dimension_source view shows the current values in the
  -- operational tables of the credential dimension.
  create view whx_credential_dimension_source as
       select -- id is the first column in the target view
              s.public_id                              as session_id,
              coalesce(scd.credential_purpose, 'None') as credential_purpose,
              cl.public_id                             as credential_library_id,
              case
                when vcl is null then 'None'
                else 'vault credential library'
                end                                    as credential_library_type,
              coalesce(vcl.name, 'None')               as credential_library_name,
              coalesce(vcl.description, 'None')        as credential_library_description,
              coalesce(vcl.vault_path, 'None')         as credential_library_vault_path,
              coalesce(vcl.http_method, 'None')        as credential_library_vault_http_method,
              coalesce(vcl.http_request_body, 'None')  as credential_library_vault_http_request_body,
              cs.public_id                             as credential_store_id,
              case
                when vcs is null then 'None'
                else 'vault credential store'
                end                                    as credential_store_type,
              coalesce(vcs.name, 'None')               as credential_store_name,
              coalesce(vcs.description, 'None')        as credential_store_description,
              coalesce(vcs.namespace, 'None')          as credential_store_vault_namespace,
              coalesce(vcs.vault_address, 'None')      as credential_store_vault_address,
              t.public_id                              as target_id,
              'tcp target'                             as target_type,
              coalesce(tt.name, 'None')                as target_name,
              coalesce(tt.description, 'None')         as target_description,
              coalesce(tt.default_port, 0)             as target_default_port_number,
              tt.session_max_seconds                   as target_session_max_seconds,
              tt.session_connection_limit              as target_session_connection_limit,
              p.public_id                              as project_id,
              coalesce(p.name, 'None')                 as project_name,
              coalesce(p.description, 'None')          as project_description,
              o.public_id                              as organization_id,
              coalesce(o.name, 'None')                 as organization_name,
              coalesce(o.description, 'None')          as organization_description
       from session_credential_dynamic as scd,
            session as s,
            credential_library as cl,
            credential_store as cs,
            credential_vault_library as vcl,
            credential_vault_store as vcs,
            target as t,
            target_tcp as tt,
            iam_scope as p,
            iam_scope as o
      where scd.library_id = cl.public_id
        and cl.store_id = cs.public_id
        and vcl.public_id = cl.public_id
        and vcs.public_id = cs.public_id
        and s.public_id = scd.session_id
        and s.target_id = t.public_id
        and t.public_id = tt.public_id
        and p.public_id = t.scope_id
        and p.type = 'project'
        and o.public_id = p.parent_id
        and o.type = 'org';

  -- Replaced in 63/03_wh_ssh_cert_library.up.sql
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
commit;
