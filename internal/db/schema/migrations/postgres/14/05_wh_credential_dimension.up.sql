begin;
  create view whx_credential_dimension_source as
       select -- id is the first column in the target view
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
         from credential_library as cl
    left join credential_store          as cs  on cl.store_id   = cs.public_id
    left join credential_vault_library  as vcl on cl.public_id  = vcl.public_id
    left join credential_vault_store    as vcs on cs.public_id  = vcs.public_id
    left join target_credential_library as tcl on cl.public_id  = tcl.credential_library_id
    left join target                    as t   on tcl.target_id = t.public_id
    left join target_tcp                as tt  on tcl.target_id = tt.public_id
    left join iam_scope                 as p   on p.public_id   = t.scope_id
    left join iam_scope                 as o   on p.parent_id   = o.public_id
        where p.type = 'project'
          and o.type = 'org';

  create view whx_credential_dimension_target as
  select key,
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

  create view whx_credential_group_source as
      select * from whx_credential_dimension_source;

  create view whx_credential_group_target as
       select m.credential_group_key                        as credential_group_key,
              m.credential_key                              as credential_key,
              m.credential_purpose                          as credential_purpose,
              cd.credential_library_id                      as credential_library_id,
              cd.credential_library_type                    as credential_library_type,
              cd.credential_library_name                    as credential_library_name,
              cd.credential_library_description             as credential_library_description,
              cd.credential_library_vault_path              as credential_library_vault_path,
              cd.credential_library_vault_http_method       as credential_library_vault_http_method,
              cd.credential_library_vault_http_request_body as credential_library_vault_http_request_body,
              cd.credential_store_id                        as credential_store_id,
              cd.credential_store_type                      as credential_store_type,
              cd.credential_store_name                      as credential_store_name,
              cd.credential_store_description               as credential_store_description,
              cd.credential_store_vault_namespace           as credential_store_vault_namespace,
              cd.credential_store_vault_address             as credential_store_vault_address,
              cd.target_id                                  as target_id,
              cd.target_type                                as target_type,
              cd.target_name                                as target_name,
              cd.target_description                         as target_description,
              cd.target_default_port_number                 as target_default_port_number,
              cd.target_session_max_seconds                 as target_session_max_seconds,
              cd.target_session_connection_limit            as target_session_connection_limit,
              cd.project_id                                 as project_id,
              cd.project_name                               as project_name,
              cd.project_description                        as project_description,
              cd.organization_id                            as organization_id,
              cd.organization_name                          as organization_name,
              cd.organization_description                   as organization_description
         from wh_credential_group as cg
    left join wh_credential_group_membership  as m  on cg.key = m.credential_group_key
    left join whx_credential_dimension_target as cd on cd.key = m.credential_key;
commit;
