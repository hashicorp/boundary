-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(12);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- setup target to use a ipv4 static address
  insert into target_address
    (target_id, address)
  values
    ('t_________wb', '8.6.4.2');

  -- insert first session, should result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's1____walter');
  insert into session_target_address
    (session_id, target_id)
  values
    ('s1____walter', 't_________wb');
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- expected wh_network_address_dimension row is created for ipv4
  select is(count(*), 1::bigint) from wh_network_address_dimension
    where address = '8.6.4.2'
        and address_type = 'IP Address'
        and ip_address_family = 'IPv4'
        and private_ip_address_indicator = 'Public IP address'
        and dns_name = 'Not Applicable'
        and ip4_address = '8.6.4.2'
        and ip6_address = 'Not Applicable';

  -- expected wh_network_address_group_membership has one row: '8.6.4.2'
  select is(count(*), 1::bigint) 
    from wh_network_address_group_membership gm,
      wh_host_dimension h
    where h.network_address_group_key = gm.network_address_group_key
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable'
      and h.host_catalog_id = 'Not Applicable'
      and h.target_id = 't_________wb';

  -- update target address association to ipv6
  update target_address set address = 'fe60::6667:5556:4445:3334' where target_id = 't_________wb';
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's2____walter');
  insert into session_target_address
    (session_id, target_id)
  values
    ('s2____walter', 't_________wb');

  -- should not result in a new host dimension
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- expected wh_network_address_dimension row is created for ipv6
  select is(count(*), 1::bigint) from wh_network_address_dimension
    where address = 'fe60::6667:5556:4445:3334'
        and address_type = 'IP Address'
        and ip_address_family = 'IPv6'
        and private_ip_address_indicator = 'Public IP address'
        and dns_name = 'Not Applicable'
        and ip4_address = 'Not Applicable'
        and ip6_address = 'fe60::6667:5556:4445:3334';

  -- expected wh_network_address_group_membership has two rows: '8.6.4.2' & 'fe60::6667:5556:4445:3334'
  select is(count(*), 2::bigint) 
    from wh_network_address_group_membership gm,
      wh_host_dimension h
    where h.network_address_group_key = gm.network_address_group_key
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable'
      and h.host_catalog_id = 'Not Applicable'
      and h.target_id = 't_________wb';

  -- update static address association to dns name
  update target_address set address = '0.blue.green' where target_id = 't_________wb';
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's3____walter');
  insert into session_target_address
    (session_id, target_id)
  values
    ('s3____walter', 't_________wb');

  -- should not result in a new host dimension
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- expected wh_network_address_dimension row is created for dns
  select is(count(*), 1::bigint) from wh_network_address_dimension
    where address = '0.blue.green'
        and address_type = 'DNS Name'
        and ip_address_family = 'Not Applicable'
        and private_ip_address_indicator = 'Not Applicable'
        and dns_name = '0.blue.green'
        and ip4_address = 'Not Applicable'
        and ip6_address = 'Not Applicable';

  -- expected wh_network_address_group_membership has three rows: '8.6.4.2' & 'fe60::6667:5556:4445:3334' & '0.blue.green'
  select is(count(*), 3::bigint) 
    from wh_network_address_group_membership gm,
      wh_host_dimension h
    where h.network_address_group_key = gm.network_address_group_key
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable'
      and h.host_catalog_id = 'Not Applicable'
      and h.target_id = 't_________wb';

  -- create second session with the same resources
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's4____walter');
  insert into session_target_address
    (session_id, target_id)
  values
    ('s4____walter', 't_________wb');

  -- should not result in a new host dimension
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- expected wh_network_address_group_membership does not change.
  select is(count(*), 3::bigint) 
    from wh_network_address_group_membership gm,
      wh_host_dimension h
    where h.network_address_group_key = gm.network_address_group_key
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable'
      and h.host_catalog_id = 'Not Applicable'
      and h.target_id = 't_________wb';

  select * from finish();
rollback;