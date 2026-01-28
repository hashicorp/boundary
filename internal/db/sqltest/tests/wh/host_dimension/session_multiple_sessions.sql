-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_multiple_sessions tests the wh_host_dimesion when
-- multiple sessions are created using the same user and auth method.
begin;
  select plan(6);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-plghs', 'h_____wb__02-plgh');
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's2____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s2____walter', 's___1wb-plghs', 'h_____wb__02-plgh');
  
  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * different user
  --  * same auth
  --  * same host
  -- should not result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____warren' , 'tok___warren' , 'abc'::bytea , 'ep1'     , 's3____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s3____walter', 's___1wb-plghs', 'h_____wb__02-plgh');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  --  * host has a different set of addresses
  insert into host_dns_name
  (host_id, name)
  values
    ('h_____wb__02-plgh', 'new.big.widget');

  -- should result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's4____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s4____walter', 's___1wb-plghs', 'h_____wb__02-plgh');

  select is(count(*), 2::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  --  * host has a different set of addresses with ipv6
  insert into host_ip_address
  (host_id, address)
  values
    ('h_____wb__02-plgh', 'fe80::beef:1111:2222:333');

  -- should result in a new host dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's5____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s5____walter', 's___1wb-plghs', 'h_____wb__02-plgh');

  select is(count(*), 3::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;

