-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_update tests the wh_user_dimesion when
-- a session is inserted and then updated.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- existing dimension via auth tokens
  select is(count(*), 4::bigint)
    from wh_user_dimension
   where user_id = 'u_____walter';

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 4::bigint)
    from wh_user_dimension
   where user_id = 'u_____walter';

  -- update session, should not impact wh_user_dimension
  update session set
    version = 2
  where
    public_id = 's1____walter';

  select is(count(*), 4::bigint)
    from wh_user_dimension
   where user_id = 'u_____walter';

  select * from finish();
rollback;
