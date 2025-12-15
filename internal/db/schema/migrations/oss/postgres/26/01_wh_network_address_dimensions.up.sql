-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_network_address_dimension contains the addresses and calculated values
  -- about those addresses.
  create table wh_network_address_dimension (
    address                      wh_dim_text primary key,
    address_type                 wh_dim_text, -- (IP Address, DNS Name, Unknown)
    ip_address_family            wh_dim_text, -- (IPv4, IPv6, Not Applicable)
    private_ip_address_indicator wh_dim_text, -- ("Public IP address", "Private IP address", "Not Applicable")
    dns_name                     wh_dim_text,
    ip4_address                  wh_dim_text,
    ip6_address                  wh_dim_text
  );

  -- wh_network_address_group is referenced by the wh_host_dimension to id
  -- the group of addresses on a host at the time a session is created.
  create table wh_network_address_group (
    key wh_dim_key primary key default wh_dim_key()
  );

  -- wh_network_address_group_membership groups the addresses
  create table wh_network_address_group_membership (
    network_address_group_key wh_dim_key
      constraint wh_network_address_group_fkey
        references wh_network_address_group (key)
        on delete restrict
        on update cascade,
    network_address wh_dim_text
      constraint wh_network_address_dimension_fkey
        references wh_network_address_dimension (address)
        on delete restrict
        on update cascade,
    primary key(network_address_group_key, network_address)
  );

  -- Get all the previously used warehouse specific labels for addresses which
  -- could not be captured by the warehousing system at some point in time.
  insert into wh_network_address_dimension(
    address, address_type, ip_address_family, private_ip_address_indicator,
    dns_name, ip4_address, ip6_address
  )
  values
    ('Unsupported', 'Unknown', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable'),
    ('Unknown', 'Unknown', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable');

  -- prepare a group which can be referenced by the newly created
  -- wh_host_dimension column.
  insert into wh_network_address_group(key)
  values('Unknown'), ('Unsupported'), ('No Addresses');
  insert into wh_network_address_group_membership(network_address_group_key, network_address)
  values('Unknown', 'Unknown'), ('Unsupported', 'Unsupported');

  -- Allow the host dimension to reference a group of addresses as referenced
  -- above.
  alter table wh_host_dimension
    add column network_address_group_key wh_dim_key not null default 'Unknown'
      constraint wh_network_address_group_fkey
        references wh_network_address_group(key)
        on delete restrict
        on update cascade;

  alter table wh_host_dimension
    alter column network_address_group_key drop default;

  -- wh_try_cast_inet returns either the provided text cast into inet or a null.
  create function wh_try_cast_inet(text) returns inet
  as $$
  begin
    return cast($1 as inet);
  exception when others then
    return null::inet;
  end;
  $$ language plpgsql
    immutable
    returns null on null input;

  -- wh_private_address_indicator returns a warehouse appropriate string
  -- representing if the address is private or public.
  create function wh_private_address_indicator(inet) returns text
  as $$
  begin
    case
      when $1 << any ('{10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, fc00::/7, fe80::/10}'::cidr[]) then
        return 'Private IP address';
      else
        return 'Public IP address';
      end case;
  end;
  $$ language plpgsql
    immutable
    returns null on null input;

  -- Migrate all the ip addresses and ignore any addresses which aren't ip.
  with
    ip_addresses(address, inet_address) as (
      select hd.host_address as address, wh_try_cast_inet(hd.host_address) as inet_address
      from wh_host_dimension as hd
      where wh_try_cast_inet(hd.host_address) is not null
    )
  insert into wh_network_address_dimension(
    address,
    address_type,
    ip_address_family,
    private_ip_address_indicator,
    dns_name,
    ip4_address,
    ip6_address
  )
  select distinct
    address,
    'IP Address',
    case
      when family(inet_address) = 4 then 'IPv4'
      when family(inet_address) = 6 then 'IPv6'
      else 'Not Applicable'
    end,
    wh_private_address_indicator(inet_address),
    'Not Applicable',
    case
      when family(inet_address) = 4 then address
      else 'Not Applicable'
    end,
    case
      when family(inet_address) = 6 then address
      else 'Not Applicable'
    end
  from ip_addresses;

  -- Everything else left to migrate is a dns name.
  insert into wh_network_address_dimension(
    address,           address_type,
    ip_address_family, private_ip_address_indicator,
    dns_name,
    ip4_address,       ip6_address
  )
  select distinct
    whd.host_address,  'DNS Name',
    'Not Applicable',  'Not Applicable',
    whd.host_address,
    'Not Applicable',  'Not Applicable'
  from wh_host_dimension as whd
  where
      whd.host_address not in (select address from wh_network_address_dimension);

  insert into wh_network_address_group (key)
  select distinct
    host_address
  from wh_host_dimension
  where host_address not in ('Unknown', 'Unsupported');

  insert into wh_network_address_group_membership(network_address_group_key, network_address)
  select distinct
    host_address, host_address
  from wh_host_dimension
  where host_address not in ('Unknown', 'Unsupported');

  update wh_host_dimension
  set network_address_group_key = host_address;

commit;
