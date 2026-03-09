-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- target tests teh whx_host_dimension_target view.
begin;
  select plan(2);

  select is_empty($$
    select * from whx_host_dimension_target
     where host_id     = 'h_____wb__01'
       and host_set_id = 's___2wb-sths'
       and target_id   = 't_________wb';
  $$);

  insert into wh_network_address_dimension
    (address, address_type, ip_address_family, private_ip_address_indicator, dns_name, ip4_address, ip6_address)
  values
    ('1.big.widget', 'DNS Name', 'Not Applicable', 'Not Applicable', '1.big.widget', 'Not Applicable', 'Not Applicable');

  insert into wh_network_address_group
    (key)
  values
    ('nagk____1_big_widget');

  insert into wh_network_address_group_membership
    (network_address_group_key, network_address)
  values
    ('nagk____1_big_widget', '1.big.widget');

  insert into wh_host_dimension
    (
      key,                   network_address_group_key,
      host_id,               host_type,                 host_name,                host_description,
      host_set_id,           host_set_type,             host_set_name,            host_set_description,
      host_catalog_id,       host_catalog_type,         host_catalog_name,        host_catalog_description,
      target_id,             target_type,               target_name,              target_description,       target_default_port_number, target_session_max_seconds, target_session_connection_limit,
      project_id,            project_name,              project_description,
      organization_id,       organization_name,         organization_description,
      current_row_indicator, row_effective_time,        row_expiration_time
    )
  values
    (
      'whd_____1',    'nagk____1_big_widget',
      'h_____wb__01', 'static host',                   'None',                      'None',
      's___2wb-sths', 'static host set',               'Big Widget Static Set 2',   'None',
      'c___wb-sthcl', 'static host catalog',           'Big Widget Static Catalog', 'None',
      't_________wb', 'tcp target',                    'Big Widget Target',         'None', 0,              28800, 1,
      'p____bwidget', 'Big Widget Factory',            'None',
      'o_____widget', 'Widget Inc',                    'None',
      'Expired',      '2021-07-21T11:01'::timestamptz, '2021-07-21T12:01'::timestamptz
    ),
    (
      'whd_____2',    'nagk____1_big_widget',
      'h_____wb__01', 'static host',                   'None',                      'None',
      's___2wb-sths', 'static host set',               'Big Widget Static Set 2',   'None',
      'c___wb-sthcl', 'static host catalog',           'Big Widget Static Catalog', 'None',
      't_________wb', 'tcp target',                    'Big Widget Target',         'None', 0,              28800, 1,
      'p____bwidget', 'Big Widget Factory',            'None',
      'o_____widget', 'Widget Inc',                    'None',
      'Current',      '2021-07-21T12:01'::timestamptz, 'infinity'::timestamptz
    );

  select is(t.*, row(
    'whd_____2',    'nagk____1_big_widget',
    'h_____wb__01', 'static host',         'None',                      'None',
    's___2wb-sths', 'static host set',     'Big Widget Static Set 2',   'None',
    'c___wb-sthcl', 'static host catalog', 'Big Widget Static Catalog', 'None',
    't_________wb', 'tcp target',          'Big Widget Target',         'None', 0,              28800, 1,
    'p____bwidget', 'Big Widget Factory',  'None',
    'o_____widget', 'Widget Inc',          'None'
  )::whx_host_dimension_target)
    from whx_host_dimension_target as t
   where t.host_id     = 'h_____wb__01'
     and t.host_set_id = 's___2wb-sths'
     and t.target_id   = 't_________wb';

  select * from finish();
rollback;

