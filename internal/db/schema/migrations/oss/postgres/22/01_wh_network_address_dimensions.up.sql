begin;

  -- wh_network_address_dimension contains the addresses and calculated values
  -- about those addresses.
  create table wh_network_address_dimension (
    address                   wh_dim_text primary key,
    address_type              wh_dim_text, --(IP Address, DNS Name, Unknown)
    ip_address_family         wh_dim_text, -- (IPv4, IPv6, Not Applicable)
    private_ip_address_status wh_dim_text, -- (Public, Private, Not Applicable)
    dns_name                  wh_dim_text,
    ip4_address               wh_dim_text,
    ip6_address               wh_dim_text
  );

  -- wh_network_address_group is referenced by the wh_host_dimension to id
  -- the group of addresses on a host at the time a session is created.
  create table wh_network_address_group (
    key wh_dim_key primary key default wh_dim_key()
  );

  -- wh_network_address_group_membership groups the addresses
  create table wh_network_address_group_membership (
    network_address_group_key wh_dim_key
      references wh_network_address_group (key)
        on delete restrict
        on update cascade,
    network_address wh_dim_text
      references wh_network_address_dimension (address)
        on delete restrict
        on update cascade,
    primary key(network_address_group_key, network_address)
  );

  -- Get all the previously used warehouse specific labels for addresses which
  -- could not be captured by the warehousing system at some point in time.
  insert into wh_network_address_dimension(
    address, address_type, ip_address_family, private_ip_address_status,
    dns_name, ip4_address, ip6_address
  )
  values
    ('Unsupported', 'Unknown', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable'),
    ('Unknown', 'Unknown', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable', 'Not Applicable');

  -- prepare a group which can be referenced by the newly created
  -- wh_host_dimension column.
  insert into wh_network_address_group(key)
  values('Unknown'), ('Unsupported');
  insert into wh_network_address_group_membership(network_address_group_key, network_address)
  values('Unknown', 'Unknown'), ('Unsupported', 'Unsupported');

  -- Allow the host dimension to reference a group of addresses as referenced
  -- above.
  alter table wh_host_dimension
    add column network_address_group_key wh_dim_key not null
      default 'Unknown'
      references wh_network_address_group(key)
        on delete restrict
        on update cascade;

commit;
