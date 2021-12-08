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

commit;
