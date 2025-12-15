-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_multiple_sessions_differnt_auth tests the wh_user_dimesion when
-- multiple sessions are created using the same user
-- but different auth accounts.
begin;
  select plan(19);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- existing dimensions from auth tokens
  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*), 8::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * different auth account
  --  * same host
  -- should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok1__walter' , 'abc'::bytea , 'ep1'    , 's4____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s4____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*),                      8::bigint)                from wh_user_dimension where user_organization_id = 'o_____widget';
  select is(count(*),                      1::bigint)                from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select is(user_id,                       'u_____walter')           from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(user_name,                     'Walter')                 from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(user_description,              'None')                   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select is(auth_account_id,               'apa1__walter')           from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_account_type,             'password auth account')  from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_account_name,             'None')                   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_account_description,      'None')                   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select is(auth_method_id,                'apm1__widget')           from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_method_type,              'password auth method')   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_method_name,              'Widget Auth Password 1') from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(auth_method_description,       'None')                   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select is(user_organization_id,          'o_____widget')           from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(user_organization_name,        'Widget Inc')             from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';
  select is(user_organization_description, 'None')                   from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select is(current_row_indicator,         'Current')                from wh_user_dimension where user_id              = 'u_____walter' and auth_account_id = 'apa1__walter';

  select * from finish();
rollback;

