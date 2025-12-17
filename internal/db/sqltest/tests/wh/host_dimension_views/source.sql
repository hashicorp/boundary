-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- source tests the whx_host_dimension_source view.
begin;
  select plan(3);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- Static hosts
  select is(s.*, row(
    'h_____wb__01', 'static host',         'None',                      'None',
    's___2wb-sths', 'static host set',     'Big Widget Static Set 2',   'None',
    'c___wb-sthcl', 'static host catalog', 'Big Widget Static Catalog', 'None',
    't_________wb', 'tcp target',          'Big Widget Target',         'None', 0,              28800, -1,
    'p____bwidget', 'Big Widget Factory',  'None',
    'o_____widget', 'Widget Inc',          'None'
  )::whx_host_dimension_source)
    from whx_host_dimension_source as s
   where s.host_id     = 'h_____wb__01'
     and s.host_set_id = 's___2wb-sths'
     and s.target_id   = 't_________wb';

  -- Plugin based hosts
  select is(s.*, row(
    'h_____wb__01-plgh',  'plugin host',         'None',                      'None',
    's___2wb-plghs',      'plugin host set',     'Big Widget Plugin Set 2',   'None',
    'c___wb-plghcl',      'plugin host catalog', 'Big Widget Plugin Catalog', 'None',
    't_________wb',       'tcp target',          'Big Widget Target',         'None', 0,              28800, -1,
    'p____bwidget',       'Big Widget Factory',  'None',
    'o_____widget',       'Widget Inc',          'None'
    )::whx_host_dimension_source)
  from whx_host_dimension_source as s
  where s.host_id     = 'h_____wb__01-plgh'
    and s.host_set_id = 's___2wb-plghs'
    and s.target_id   = 't_________wb';


-- network address dimension
  declare cwant cursor for select
      address, address_type, ip_address_family, private_ip_address_indicator,
      dns_name, ip4_address, ip6_address
  from whx_network_address_dimension_source
  where host_id = 'h_____wb__02-plgh'
  order by address;

  select results_eq(
    'cwant'::refcursor,
    $$VALUES
     ('2.big.widget', 'DNS Name',   'Not Applicable', 'Not Applicable',
     '2.big.widget',  'Not Applicable', 'Not Applicable'),
     ('fe80::2222:2222:2222:2222',      'IP Address', 'IPv6',  'Private IP address',
    'Not Applicable', 'Not Applicable', 'fe80::2222:2222:2222:2222')
    $$);

  select * from finish();
rollback;

