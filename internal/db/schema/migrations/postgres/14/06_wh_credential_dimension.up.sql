begin;
  create function _distinct_credentials(p_target_id wt_public_id)
    returns bool
  as $$
  declare
    src_count    bigint;
    target_count bigint;
    src          whx_credential_group_target%rowtype;
    target       whx_credential_group_target%rowtype;
  begin
    select count(*) into target_count
      from whx_credential_group_target as t
      where t.target_id = p_target_id;

    select count(*) into src_count
      from whx_credential_group_source as s
    where s.target_id = p_target_id;

    if target_count != src_count then
      return true;
    end if;

    for target in
      select *
        from whx_credential_group_target as t
        where t.target_id = p_target_id
    loop
      select target.credential_group_key, target.credential_key, target.credential_purpose, s.* into src
        from whx_credential_dimension_source as s
      where s.target_id             = p_target_id
        and s.credential_library_id = target.credential_library_id;

      if src is distinct from target then
        return true;
      end if;
    end loop;

    return false;
  end;
  $$ language plpgsql;

  create function wh_upsert_credential_group(p_target_id wt_public_id)
    returns wh_dim_id
  as $$
  declare
    src           whx_credential_dimension_source%rowtype;
    target        whx_credential_group_target%rowtype;
    new_row       wh_credential_group%rowtype;
    dimension_key wh_dim_id;
  begin
    if _distinct_credentials(p_target_id) then
      -- expire the current rows
      for target in
        select * from whx_credential_group_target as t
                where t.target_id = p_target_id
      loop
        update wh_credential_dimension
           set current_row_indicator = 'Expired',
               row_expiration_time   = current_timestamp
        where key = target.credential_key
          and current_row_indicator = 'Current';
      end loop;

      -- insert new group
      insert into wh_credential_group default values returning * into new_row;

      for src in
        select * from whx_credential_dimension_source where target_id = p_target_id
      loop
        -- insert new credential dimensions
        insert into wh_credential_dimension (
               credential_library_id,     credential_library_type,     credential_library_name,      credential_library_description,     credential_library_vault_path,        credential_library_vault_http_method,     credential_library_vault_http_request_body,
               credential_store_id,       credential_store_type,       credential_store_name,        credential_store_description,       credential_store_vault_namespace,     credential_store_vault_address,
               target_id,                 target_type,                 target_name,                  target_description,                 target_default_port_number,           target_session_max_seconds,               target_session_connection_limit,
               project_id,                project_name,                project_description,
               organization_id,           organization_name,           organization_description,
               current_row_indicator,     row_effective_time,          row_expiration_time
        )
        values (
               src.credential_library_id, src.credential_library_type, src.credential_library_name,  src.credential_library_description, src.credential_library_vault_path,    src.credential_library_vault_http_method, src.credential_library_vault_http_request_body,
               src.credential_store_id,   src.credential_store_type,   src.credential_store_name,    src.credential_store_description,   src.credential_store_vault_namespace, src.credential_store_vault_address,
               src.target_id,             src.target_type,             src.target_name,              src.target_description,             src.target_default_port_number,       src.target_session_max_seconds,           src.target_session_connection_limit,
               src.project_id,            src.project_name,            src.project_description,
               src.organization_id,       src.organization_name,       src.organization_description,
               'Current',                 current_timestamp,           'infinity'::timestamptz
        )
        returning key into dimension_key;

        insert into wh_credential_group_membership
          (credential_group_key, credential_key, credential_purpose)
        values
          (new_row.key,          dimension_key,  'application');
      end loop;

      return new_row.key;
    end if;

    return target.credential_group_key;
  end;
  $$ language plpgsql;
commit;
