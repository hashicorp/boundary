-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- dropping these foreign keys because they were never needed
  alter table target_tcp drop constraint target_tcp_scope_id_fkey;

  alter table target rename column scope_id to project_id;
  drop trigger immutable_columns on target;
  create trigger immutable_columns before update on target
    for each row execute function immutable_columns('public_id', 'project_id', 'create_time');

  -- insert_target_subtype() is a before insert trigger function for subtypes of
  -- target.
  -- Replaces the insert_target_subtype function defined in 0/40_targets.up.sql
  create or replace function insert_target_subtype() returns trigger
  as $$
  begin
    insert into target
      (public_id, project_id)
    values
      (new.public_id, new.project_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_target_subtype() is
    'insert_target_subtype() is a before insert trigger function that should be added to all target subtype tables.';

  -- target_scope_valid() is a before insert trigger function for target
  -- Replaces the target_scope_valid function defined in 0/40_targets.up.sql
  -- Dropped in 45/03_targets.up.sql
  create or replace function target_scope_valid() returns trigger
  as $$
  declare
      scope_type text;
  begin
    -- Fetch the type of scope
    select type into scope_type
      from iam_scope
     where public_id = new.project_id;

    if scope_type = 'project' then
      return new;
    end if;
    raise exception 'invalid target scope type % (must be project)', scope_type;
  end;
  $$ language plpgsql;

  alter table target_tcp rename column scope_id to project_id;
  alter table target_tcp rename constraint target_tcp_scope_id_name_key to target_tcp_project_id_name_uq;
  drop trigger immutable_columns on target_tcp;
  create trigger immutable_columns before update on target_tcp
    for each row execute function immutable_columns('public_id', 'project_id', 'create_time');

  -- target_host_set_scope_valid() is a before insert trigger function for target_host_set
  -- Replaces target_host_set_scope_valid defined in 44/02_hosts.up.sql
  create or replace function target_host_set_scope_valid() returns trigger
  as $$
  declare
    host_set_project_id wt_scope_id;
    target_project_id wt_scope_id;
  begin

    select hc.project_id into host_set_project_id
      from host_set hs
      join host_catalog hc on hs.catalog_id = hc.public_id
     where hs.public_id = new.host_set_id;

    select target.project_id into target_project_id
      from target
     where target.public_id = new.target_id;

    if target_project_id = host_set_project_id then
      return new;
    end if;
    raise exception 'target and host set are not in the same scope' using
          errcode = '23000',
          schema  = tg_table_schema,
          table   = tg_table_name;

  end;
  $$ language plpgsql;

  -- warehouse

  -- Replaces whx_host_dimension_source defined in 26/02_wh_network_address_dimensions.up.sql.
  -- Replaced view in 60/03_wh_sessions.up.sql
  drop view whx_host_dimension_source;
  create view whx_host_dimension_source as
  select -- id is the first column in the target view
         h.public_id                     as host_id,
         case when sh.public_id is not null then 'static host'
              when ph.public_id is not null then 'plugin host'
              else 'Unknown' end          as host_type,
         case when sh.public_id is not null then coalesce(sh.name, 'None')
              when ph.public_id is not null then coalesce(ph.name, 'None')
              else 'Unknown' end          as host_name,
         case when sh.public_id is not null then coalesce(sh.description, 'None')
              when ph.public_id is not null then coalesce(ph.description, 'None')
              else 'Unknown' end          as host_description,

         hs.public_id                     as host_set_id,
         case when shs.public_id is not null then 'static host set'
              when phs.public_id is not null then 'plugin host set'
              else 'Unknown' end          as host_set_type,
         case
           when shs.public_id is not null then coalesce(shs.name, 'None')
           when phs.public_id is not null then coalesce(phs.name, 'None')
           else 'None'
           end                            as host_set_name,
         case
           when shs.public_id is not null then coalesce(shs.description, 'None')
           when phs.public_id is not null then coalesce(phs.description, 'None')
           else 'None'
           end                            as host_set_description,
         hc.public_id                     as host_catalog_id,
         case when shc.public_id is not null then 'static host catalog'
              when phc.public_id is not null then 'plugin host catalog'
              else 'Unknown' end          as host_catalog_type,
         case
           when shc.public_id is not null then coalesce(shc.name, 'None')
           when phc.public_id is not null then coalesce(phc.name, 'None')
           else 'None'
           end                            as host_catalog_name,
         case
           when shc.public_id is not null then coalesce(shc.description, 'None')
           when phc.public_id is not null then coalesce(phc.description, 'None')
           else 'None'
           end                            as host_catalog_description,
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
  from host as h
    join host_catalog as hc                on h.catalog_id = hc.public_id
    join host_set as hs                    on h.catalog_id = hs.catalog_id
    join target_host_set as ts             on hs.public_id = ts.host_set_id
    join target_tcp as t                   on ts.target_id = t.public_id
    join iam_scope as p                    on t.project_id = p.public_id and p.type = 'project'
    join iam_scope as o                    on p.parent_id = o.public_id and o.type = 'org'

    left join static_host as sh            on sh.public_id = h.public_id
    left join host_plugin_host as ph       on ph.public_id = h.public_id
    left join static_host_catalog as shc   on shc.public_id = hc.public_id
    left join host_plugin_catalog as phc   on phc.public_id = hc.public_id
    left join static_host_set as shs       on shs.public_id = hs.public_id
    left join host_plugin_set as phs       on phs.public_id = hs.public_id
  ;

  -- The whx_credential_dimension_source view shows the current values in the
  -- operational tables of the credential dimension.
  -- Replaces whx_credential_dimension_source defined in 16/02_wh_credential_dimension.up.sql
  -- Replaced in 63/03_wh_ssh_cert_library.up.sql
  drop view whx_credential_dimension_source;
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
        and p.public_id = t.project_id
        and p.type = 'project'
        and o.public_id = p.parent_id
        and o.type = 'org';

  -- Replaces target_all_subtypes defined in 1/01_server_tags_migrations.up.sql
  -- Replaced in 59/01_target_ingress_egress_worker_filters.up.sql
  drop view target_all_subtypes;
  create view target_all_subtypes as
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         'tcp' as type
  from target_tcp;

commit;
