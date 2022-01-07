begin;

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

  -- wh_private_address_status returns a warehouse appropriate string
  -- representing if the address is private or public.
  create function wh_private_address_status(inet) returns text
  as $$
  begin
    case
      when $1 << any ('{10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, fc00::/7, fe80::/10}'::cidr[]) then
        return 'Private';
      else
        return 'Public';
      end case;
  end;
  $$ language plpgsql;

  create view whx_network_address_dimension_source as
    select
      hdns.host_id as host_id,
      hdns.name as address,
      'DNS Name' as address_type,
      'Not Applicable' as ip_address_family,
      'Not Applicable' private_ip_address_status,
      hdns.name as dns_name,
      'Not Applicable' as ip4_address,
      'Not Applicable' as ip6_address
    from host_dns_name as hdns
    union
    select -- id is the first column in the target view
       hip.host_id as host_id,
       host(hip.address) as address,
       'IP Address' as address_type,
       case
         when family(hip.address) = 4 then 'IPv4'
         when family(hip.address) = 6 then 'IPv6'
         else 'Not Applicable'
         end               as ip_address_family,
       wh_private_address_status(hip.address) as private_ip_address_status,
       'Not Applicable' as dns_name,
       case
         when hip.address is not null and family(hip.address) = 4 then host(hip.address)
         else 'Not Applicable'
         end as ip4_address,
       case
         when hip.address is not null and family(hip.address) = 6 then host(hip.address)
         else 'Not Applicable'
         end as ip6_address
    from host_ip_address as hip;

commit;
