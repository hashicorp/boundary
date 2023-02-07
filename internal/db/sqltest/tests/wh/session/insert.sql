-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- insert tests that a wh_session_accumulating_fact is created when
-- a session is created.
begin;
  select plan(2);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  select is(count(*), 0::bigint) from wh_session_accumulating_fact where session_id = 's1____walter';

  -- insert first session, should result in a new wh_session_accumulating_fact
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint ,  public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'     , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 1::bigint) from wh_session_accumulating_fact where session_id = 's1____walter';

  select * from finish();
rollback;
