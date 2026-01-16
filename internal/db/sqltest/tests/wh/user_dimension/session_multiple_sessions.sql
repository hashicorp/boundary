-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_multiple_sessions tests the wh_user_dimesion when
-- multiple sessions are created using the same user and auth method.
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- existing dimensions from auth tokens
  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     , user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's2____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s2____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * different host
  -- should not result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's3____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s3____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  select * from finish();
rollback;
