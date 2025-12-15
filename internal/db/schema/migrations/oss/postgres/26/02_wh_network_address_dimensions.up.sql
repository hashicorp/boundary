-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- replaces 20/07_wh_session_dimensions.up.sql

  -- Updates whx_host_dimension_source to not have the host address on the
  -- view and instead rely on a reference to the wh_network_address_group
  -- referenced in the wh_upsert_host function query that uses this view.
  -- Replaced in 44/03_targets.up.sql
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
    join iam_scope as p                    on t.scope_id = p.public_id and p.type = 'project'
    join iam_scope as o                    on p.parent_id = o.public_id and o.type = 'org'

    left join static_host as sh            on sh.public_id = h.public_id
    left join host_plugin_host as ph       on ph.public_id = h.public_id
    left join static_host_catalog as shc   on shc.public_id = hc.public_id
    left join host_plugin_catalog as phc   on phc.public_id = hc.public_id
    left join static_host_set as shs       on shs.public_id = hs.public_id
    left join host_plugin_set as phs       on phs.public_id = hs.public_id
  ;

  -- replaces view from 15/02_wh_rename_host_dimension_org.up.sql
  -- adds the network_address_group_key.
  drop view whx_host_dimension_target;
  create view whx_host_dimension_target as
  select key,
         network_address_group_key,
         host_id,
         host_type,
         host_name,
         host_description,
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

  create view whx_network_address_dimension_source as
    select
      hdns.host_id     as host_id,
      hdns.name        as address,
      'DNS Name'       as address_type,
      'Not Applicable' as ip_address_family,
      'Not Applicable' as private_ip_address_indicator,
      hdns.name        as dns_name,
      'Not Applicable' as ip4_address,
      'Not Applicable' as ip6_address
    from host_dns_name as hdns
    union
    select -- id is the first column in the target view
       hip.host_id       as host_id,
       host(hip.address) as address,
       'IP Address'      as address_type,
       case
         when family(hip.address) = 4 then 'IPv4'
         when family(hip.address) = 6 then 'IPv6'
         else 'Not Applicable'
       end               as ip_address_family,
       wh_private_address_indicator(hip.address) as private_ip_address_indicator,
       'Not Applicable'  as dns_name,
       case
         when hip.address is not null and family(hip.address) = 4 then host(hip.address)
         else 'Not Applicable'
       end               as ip4_address,
       case
         when hip.address is not null and family(hip.address) = 6 then host(hip.address)
         else 'Not Applicable'
       end               as ip6_address
    from host_ip_address as hip
    union
    select
      sh.public_id     as host_id,
      sh.address       as address,
      'DNS Name'       as address_type,
      'Not Applicable' as ip_address_family,
      'Not Applicable' as private_ip_address_indicator,
      sh.address       as dns_name,
      'Not Applicable' as ip4_address,
      'Not Applicable' as ip6_address
    from static_host as sh
    where wh_try_cast_inet(sh.address) is null
    union
    select
      sh.public_id     as host_id,
      host(wh_try_cast_inet(sh.address)) as address,
      'IP Address'     as address_type,
      case
        when family(wh_try_cast_inet(sh.address)) = 4 then 'IPv4'
        when family(wh_try_cast_inet(sh.address)) = 6 then 'IPv6'
        else 'Not Applicable'
      end              as ip_address_family,
      wh_private_address_indicator(wh_try_cast_inet(sh.address)) as private_ip_address_indicator,
      'Not Applicable' as dns_name,
      case
        when family(wh_try_cast_inet(sh.address)) = 4 then host(wh_try_cast_inet(sh.address))
        else 'Not Applicable'
      end              as ip4_address,
      case
        when family(wh_try_cast_inet(sh.address)) = 6 then host(wh_try_cast_inet(sh.address))
        else 'Not Applicable'
      end              as ip6_address
    from static_host as sh
    where wh_try_cast_inet(sh.address) is not null;

  alter table wh_host_dimension
    drop column host_address;

commit;
