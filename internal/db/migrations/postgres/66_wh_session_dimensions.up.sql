begin;

  create or replace function wh_upsert_host(p_host_id wt_public_id, p_host_set_id wt_public_id, p_target_id wt_public_id)
    returns wh_dim_id
  as $$
  declare
    src whx_host_dimension_target%rowtype;
    target whx_host_dimension_target%rowtype;
    new_row wh_host_dimension%rowtype;
  begin
    select * into target
      from whx_host_dimension_target as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    select target.id, t.* into src
      from whx_host_dimension_source as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    if src is distinct from target then

      -- expire the current row
      update wh_host_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_host_dimension (
             host_id,               host_type,              host_name,                     host_description,         host_address,
             host_set_id,           host_set_type,          host_set_name,                 host_set_description,
             host_catalog_id,       host_catalog_type,      host_catalog_name,             host_catalog_description,
             target_id,             target_type,            target_name,                   target_description,
             project_id,            project_name,           project_description,
             host_organization_id,  host_organization_name, host_organization_description,
             current_row_indicator, row_effective_time,     row_expiration_time
      )
      select host_id,               host_type,              host_name,                     host_description,         host_address,
             host_set_id,           host_set_type,          host_set_name,                 host_set_description,
             host_catalog_id,       host_catalog_type,      host_catalog_name,             host_catalog_description,
             target_id,             target_type,            target_name,                   target_description,
             project_id,            project_name,           project_description,
             host_organization_id,  host_organization_name, host_organization_description,
             'Current',             current_timestamp,      'infinity'::timestamptz
        from whx_host_dimension_source
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
      returning * into new_row;

      return new_row.id;
    end if;
    return target.id;

  end;
  $$ language plpgsql;

commit;
