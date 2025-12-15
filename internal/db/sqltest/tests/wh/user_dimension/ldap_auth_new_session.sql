-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- ldap_auth_new_session tests the wh_user_dimesion when
-- a new session is created using the ldap auth method.
begin;
  select plan(41);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- existing dimension from auth tokens
  select is(count(*), 2::bigint)
    from wh_user_dimension
   where user_id        in ('u_____walter', 'u_____warren')
     and auth_method_id = 'alm___widget';

  -- update walter and warren so the user dimension is changed when the session is inserted
  update iam_user
     set description = 'LDAP Auth New Session'
   where public_id in ('u_____walter', 'u_____warren');

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id    ,  target_id     ,  user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____walter' , 'ldap__walter' , 'abc'::bytea , 'ep1'    , 's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');

  -- inserting the session should result in a new user dimension.
  select is(count(*), 1::bigint)
    from wh_user_dimension
   where user_id          = 'u_____walter'
     and auth_method_id   = 'alm___widget'
     and user_description = 'LDAP Auth New Session';

  select is(count(*),                      1::bigint)                  from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_id,                       'u_____walter')             from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_name,                     'Walter')                   from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_description,              'LDAP Auth New Session')    from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(auth_account_id,               'ala___walter')             from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_type,             'ldap auth account')        from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_name,             'walter account')           from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_description,      'Walter LDAP Account')      from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_external_id,      'walter')                   from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_full_name,        'Walter')                   from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_email,            'walter@widget.test')       from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(auth_method_id,                'alm___widget')             from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_type,              'ldap auth method')         from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_name,              'Widget LDAP')              from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_description,       'None')                     from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_external_id,       'Not Applicable')           from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(user_organization_id,          'o_____widget')             from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_organization_name,        'Widget Inc')               from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_organization_description, 'None')                     from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(current_row_indicator,         'Current')                  from wh_user_dimension where user_id = 'u_____walter' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(session_fact.user_key, user_dim.key)
    from wh_session_connection_accumulating_fact as session_fact,
         wh_user_dimension                       as user_dim
   where session_fact.session_id = 's1____walter'
     and user_dim.user_id        = 'u_____walter';

  -- insert session without full name or email
  insert into session
    ( project_id    ,  target_id     , user_id       ,  auth_token_id ,  certificate ,  endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 'u_____warren' , 'ldap__warren' , 'abc'::bytea , 'ep1'    , 's1____warren');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____warren', 's___1wb-sths', 'h_____wb__01');

  select is(count(*),                      1::bigint)                  from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_name,                     'Warren')                   from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_description,              'LDAP Auth New Session')    from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(auth_account_id,               'ala___warren')             from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_type,             'ldap auth account')        from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_name,             'warren account')           from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_description,      'Warren LDAP Account')      from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_external_id,      'warren')                   from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_full_name,        'None')                     from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_account_email,            'None')                     from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(auth_method_id,                'alm___widget')             from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_type,              'ldap auth method')         from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_name,              'Widget LDAP')              from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_description,       'None')                     from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(auth_method_external_id,       'Not Applicable')           from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(user_organization_id,          'o_____widget')             from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_organization_name,        'Widget Inc')               from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';
  select is(user_organization_description, 'None')                     from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select is(current_row_indicator,         'Current')                  from wh_user_dimension where user_id = 'u_____warren' and auth_method_id = 'alm___widget' and user_description = 'LDAP Auth New Session';

  select * from finish();
rollback;
