-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_upsert_network_address_dimension function writes all addresses for a
  -- host to wh_network_address_dimension if they aren't already there, creates
  -- a network address group which contains only the addresses for the
  -- provided host if one doesn't exist and returns the group key which contains
  -- exactly the set of addresses which the provided host contains.
  create function wh_upsert_network_address_dimension(p_host_id wt_public_id) returns wh_dim_key
  as $$
  declare
    nag_key wh_dim_key;
    a_key  wh_dim_key;
  begin
    if not exists (
      select 1
      from whx_network_address_dimension_source
      where host_id = p_host_id) then
      return 'No Addresses';
    end if;

    insert into wh_network_address_dimension (
      address, address_type, ip_address_family, private_ip_address_indicator, dns_name, ip4_address, ip6_address
    )
    select
      address, address_type, ip_address_family, private_ip_address_indicator, dns_name, ip4_address, ip6_address
    from whx_network_address_dimension_source
    where host_id = p_host_id
    on conflict do nothing;

    with address_list (address) as (
        select address
        from whx_network_address_dimension_source
        where host_id = p_host_id
    )
    select distinct network_address_group_key into nag_key
    from wh_network_address_group_membership o
    -- At least 1 address is in the group which is also in the address list
    where o.network_address in (select address from address_list)
      -- The number of unique addresses in this group is the same as is in the
      -- address_list.
      and (select count(address) from address_list) =
          (
            select count(i.network_address)
            from wh_network_address_group_membership i
            where o.network_address_group_key = i.network_address_group_key
          )
      -- There are no other addresses in this group which are not in the
      -- address_list.
      and not exists
      (
            select 1
            from wh_network_address_group_membership i
            where o.network_address_group_key = i.network_address_group_key
              and i.network_address not in (select address from address_list)
      )
    ;

    if nag_key is null then
      insert into wh_network_address_group default values returning key into nag_key;
      insert into wh_network_address_group_membership
      (network_address_group_key, network_address)
      select nag_key, address
      from whx_network_address_dimension_source
      where host_id = p_host_id;
    end if;
    return nag_key;

  end
  $$ language plpgsql;


  -- replaces function from 15/02_wh_rename_key_columns.up.sql
  -- replaced function in 60/03_wh_sessions.up.sql
  -- adds the network address key to the host dimension table.
  drop function wh_upsert_host;
  create function wh_upsert_host(p_host_id wt_public_id, p_host_set_id wt_public_id, p_target_id wt_public_id) returns wh_dim_key
  as $$
  declare
    src     whx_host_dimension_target%rowtype;
    target  whx_host_dimension_target%rowtype;
    new_row wh_host_dimension%rowtype;
    addr_group_key wh_dim_key;
  begin
    select * into target
    from whx_host_dimension_target as t
    where t.host_id               = p_host_id
      and t.host_set_id           = p_host_set_id
      and t.target_id             = p_target_id;

    select wh_upsert_network_address_dimension(p_host_id) into addr_group_key;

    select target.key, addr_group_key, t.* into src
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
        host_id,                    host_type,                  host_name,                       host_description,
        network_address_group_key,
        host_set_id,                host_set_type,              host_set_name,                   host_set_description,
        host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
        target_id,                  target_type,                target_name,                     target_description,
        target_default_port_number, target_session_max_seconds, target_session_connection_limit,
        project_id,                 project_name,               project_description,
        organization_id,            organization_name,          organization_description,
        current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,
             addr_group_key,
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
