-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- password_auth_new_session tests the wh_user_dimesion when
-- a new session is created using the password auth method.
begin;
  select plan(21);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension where user_organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  select is(count(*),                      1::bigint)               from wh_user_dimension where user_id = 'u_____walter';
  select is(user_id,                       'u_____walter')          from wh_user_dimension where user_id = 'u_____walter';
  select is(user_name,                     'Walter')                from wh_user_dimension where user_id = 'u_____walter';
  select is(user_description,              'None')                  from wh_user_dimension where user_id = 'u_____walter';

  select is(auth_account_id,               'apa___walter')          from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_type,             'password auth account') from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_name,             'None')                  from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_description,      'None')                  from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_external_id,      'Not Applicable')        from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_full_name,        'Not Applicable')        from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_account_email,            'Not Applicable')        from wh_user_dimension where user_id = 'u_____walter';

  select is(auth_method_id,                'apm___widget')          from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_method_type,              'password auth method')  from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_method_name,              'Widget Auth Password')  from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_method_description,       'None')                  from wh_user_dimension where user_id = 'u_____walter';
  select is(auth_method_external_id,       'Not Applicable')        from wh_user_dimension where user_id = 'u_____walter';

  select is(user_organization_id,          'o_____widget')          from wh_user_dimension where user_id = 'u_____walter';
  select is(user_organization_name,        'Widget Inc')            from wh_user_dimension where user_id = 'u_____walter';
  select is(user_organization_description, 'None')                  from wh_user_dimension where user_id = 'u_____walter';

  select is(current_row_indicator,         'Current')               from wh_user_dimension where user_id = 'u_____walter';

  select * from finish();
rollback;
