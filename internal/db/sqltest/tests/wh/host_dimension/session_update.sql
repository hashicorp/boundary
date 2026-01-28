-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_update tests the wh_host_dimesion when
-- a session is inserted and then updated.
begin;
  select plan(4);

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
    ('s1____walter', 's___1wb-plghs', 'h_____wb__01-plgh');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- update session, should not impact wh_host_dimension
  update session set
    version = 2
  where
    public_id = 's1____walter';

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  insert into host_dns_name
  (host_id, name)
  values
    ('h_____wb__01-plgh', 'new.big.widget');

  -- update session, should not impact wh_host_dimension
  update session set
    version = 2
  where
      public_id = 's1____walter';

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;
