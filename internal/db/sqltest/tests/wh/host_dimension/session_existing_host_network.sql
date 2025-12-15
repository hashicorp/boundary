-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(8);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- create network address dimension using static host
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';
  select is(count(*), 1::bigint) from wh_network_address_dimension
    where address = '1.big.widget'
        and address_type = 'DNS Name'
        and ip_address_family = 'Not Applicable'
        and private_ip_address_indicator = 'Not Applicable'
        and dns_name = '1.big.widget'
        and ip4_address = 'Not Applicable'
        and ip6_address = 'Not Applicable';
  select is(count(*), 1::bigint)
    from wh_network_address_group_membership g
    left join wh_host_dimension h on g.network_address_group_key = h.network_address_group_key
    where g.network_address = '1.big.widget'
      and h.target_id = 't_________wb'
      and h.host_id = 'h_____wb__01'
      and h.host_set_id = 's___1wb-sths'
      and h.current_row_indicator = 'Current';

  -- delete target host source associations to enforce mutually exclusive relationship to a target address
  delete from target_host_set where target_id = 't_________wb';

  -- update target to use the same address, but as a direct network address association
  insert into target_address
    (target_id, address)
  values
    ('t_________wb', '1.big.widget');
  select is(count(*), 0::bigint) from target_host_set where target_id = 't_________wb';

  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's2____walter');
  insert into session_target_address
    (session_id, target_id)
  values
    ('s2____walter', 't_________wb');

  -- this should have expired the old host_dimension that had values inserted in the columns related to hosts, host sets, & host catalogs.
  -- this should have created a new host_dimension for a static address with 'Not Applicable' values set for columns related to hosts, host sets, & host catalogs.
  -- this should have used the existing network_address_dimension created from the session using a host source
  select is(count(*), 2::bigint) from wh_host_dimension where organization_id = 'o_____widget';
  select is(count(*), 1::bigint) from wh_network_address_dimension
    where address = '1.big.widget'
        and address_type = 'DNS Name'
        and ip_address_family = 'Not Applicable'
        and private_ip_address_indicator = 'Not Applicable'
        and dns_name = '1.big.widget'
        and ip4_address = 'Not Applicable'
        and ip6_address = 'Not Applicable';
  select is(count(*), 1::bigint)
    from wh_network_address_group_membership g
    left join wh_host_dimension h on g.network_address_group_key = h.network_address_group_key
    where g.network_address = '1.big.widget'
      and h.target_id = 't_________wb'
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable'
      and h.current_row_indicator = 'Current';

  select * from finish();
rollback;