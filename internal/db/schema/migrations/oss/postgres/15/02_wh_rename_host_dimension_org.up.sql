-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  alter table wh_host_dimension
    rename column host_organization_id to organization_id;
  alter table wh_host_dimension
    rename column host_organization_name to organization_name;
  alter table wh_host_dimension
    rename column host_organization_description to organization_description;

  -- replaces view from 0/65_wh_session_dimensions.up.sql
  drop view whx_host_dimension_source;
  create view whx_host_dimension_source as
  select -- id is the first column in the target view
         h.public_id                     as host_id,
         'static host'                   as host_type,
         coalesce(h.name, 'None')        as host_name,
         coalesce(h.description, 'None') as host_description,
         coalesce(h.address, 'Unknown')  as host_address,
         s.public_id                     as host_set_id,
         'static host set'               as host_set_type,
         coalesce(s.name, 'None')        as host_set_name,
         coalesce(s.description, 'None') as host_set_description,
         c.public_id                     as host_catalog_id,
         'static host catalog'           as host_catalog_type,
         coalesce(c.name, 'None')        as host_catalog_name,
         coalesce(c.description, 'None') as host_catalog_description,
         t.public_id                     as target_id,
         'tcp target'                    as target_type,
         coalesce(t.name, 'None')        as target_name,
         coalesce(t.description, 'None') as target_description,
         coalesce(t.default_port, 0)     as target_default_port_number,
         t.session_max_seconds           as target_session_max_seconds,
         t.session_connection_limit      as target_session_connection_limit,
         p.public_id                     as project_id,
         coalesce(p.name, 'None')        as project_name,
         coalesce(p.description, 'None') as project_description,
         o.public_id                     as organization_id,
         coalesce(o.name, 'None')        as organization_name,
         coalesce(o.description, 'None') as organization_description
    from static_host as h,
         static_host_catalog as c,
         static_host_set_member as m,
         static_host_set as s,
         target_host_set as ts,
         target_tcp as t,
         iam_scope as p,
         iam_scope as o
   where h.catalog_id = c.public_id
     and h.public_id = m.host_id
     and s.public_id = m.set_id
     and t.public_id = ts.target_id
     and s.public_id = ts.host_set_id
     and p.public_id = t.scope_id
     and p.type = 'project'
     and o.public_id = p.parent_id
     and o.type = 'org'
  ;

  -- replaces view from 15/01_wh_rename_key_columns.up.sql
  -- replaced in 26/02_wh_network_address_dimensions.up.sql
  drop view whx_host_dimension_target;
  create view whx_host_dimension_target as
  select key,
         host_id,
         host_type,
         host_name,
         host_description,
         host_address,
         host_set_id,
         host_set_type,
         host_set_name,
         host_set_description,
         host_catalog_id,
         host_catalog_type,
         host_catalog_name,
         host_catalog_description,
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
    from wh_host_dimension
   where current_row_indicator = 'Current'
  ;

  -- replaces function from 15/01_wh_rename_key_columns.up.sql
  -- replaced in 26/03_wh_network_address_dimensions.up.sql
  drop function wh_upsert_host;
  create function wh_upsert_host(p_host_id wt_public_id, p_host_set_id wt_public_id, p_target_id wt_public_id) returns wh_dim_key
  as $$
  declare
    src     whx_host_dimension_target%rowtype;
    target  whx_host_dimension_target%rowtype;
    new_row wh_host_dimension%rowtype;
  begin
    select * into target
      from whx_host_dimension_target as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    select target.key, t.* into src
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
             host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             organization_id,            organization_name,          organization_description,
             current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             organization_id,            organization_name,          organization_description,
             'Current',                  current_timestamp,          'infinity'::timestamptz
        from whx_host_dimension_source
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
      returning * into new_row;

      return new_row.key;
    end if;
    return target.key;

  end;
  $$ language plpgsql;
commit;
