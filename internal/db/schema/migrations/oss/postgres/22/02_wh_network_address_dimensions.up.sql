begin;

  -- try_cast_inet returns either the provided text cast into inet or a null.
  create function try_cast_inet(text)
    returns inet
  as $$
  begin
    return cast($1 as inet);
  exception when others then
    return null::inet;
  end;
  $$ language plpgsql;

  -- wh_private_address_status returns a warehouse appropriate string
  -- representing if the address is private, public, or not applicable for the
  -- provided address.  An address which cannot be cast to an inet results in
  -- 'Not Applicable' being returned.
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

  insert into wh_network_address_dimension(
    address, address_type, ip_address_family, private_ip_address_status,
    dns_name, ip4_address, ip6_address
  )
  values
    ('Unsupported', 'Unknown', 'Not Applicable', 'Not Applicable', 'None', 'None', 'None'),
    ('Unknown', 'Unknown', 'Not Applicable', 'Not Applicable', 'None', 'None', 'None');

  with
  ip_addresses(address, inet_address) as (
    select hd.host_address as address, try_cast_inet(hd.host_address) as inet_address
    from wh_host_dimension as hd
    where try_cast_inet(hd.host_address) is not null
  )
  insert into wh_network_address_dimension(
    address, address_type, ip_address_family, private_ip_address_status,
    dns_name, ip4_address, ip6_address
  )
  select
    address,
    'IP Address',
    case
      when family(inet_address) = 4 then 'IPv4'
      when family(inet_address) = 6 then 'IPv6'
      else 'Not Applicable'
    end,
    wh_private_address_status(inet_address),
    'None',
    case
      when family(inet_address) = 4 then address
      else 'None'
    end,
    case
      when family(inet_address) = 6 then address
      else 'None'
    end
  from ip_addresses;

  insert into wh_network_address_dimension(
    address, address_type, ip_address_family, private_ip_address_status,
    dns_name, ip4_address, ip6_address
  )
  select
    whd.host_address,
    'DNS Name',
    'Not Applicable',
    'Not Applicable',
    whd.host_address,
    'None',
    'None'
  from wh_host_dimension as whd
  where
    whd.host_address not in (select address from wh_network_address_dimension);

commit;
