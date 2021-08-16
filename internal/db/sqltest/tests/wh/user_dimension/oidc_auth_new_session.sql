-- oidc_auth_new_session tests the wh_user_dimesion when
-- a new session is created using the oidc auth method.
begin;
  select plan(40);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension;

  -- insert first session, should result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'oidc__walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*),                      1::bigint)                  from wh_user_dimension;
  select is(user_id,                       'u_____walter')             from wh_user_dimension;
  select is(user_name,                     'Walter')                   from wh_user_dimension;
  select is(user_description,              'None')                     from wh_user_dimension;

  select is(auth_account_id,               'aoa___walter')             from wh_user_dimension;
  select is(auth_account_type,             'oidc auth account')        from wh_user_dimension;
  select is(auth_account_name,             'walter account')           from wh_user_dimension;
  select is(auth_account_description,      'Walter OIDC Account')      from wh_user_dimension;
  select is(auth_account_external_id,      'sub___walter')             from wh_user_dimension;
  select is(auth_account_full_name,        'Walter')                   from wh_user_dimension;
  select is(auth_account_email,            'walter@widget.test')       from wh_user_dimension;

  select is(auth_method_id,                'aom___widget')             from wh_user_dimension;
  select is(auth_method_type,              'oidc auth method')         from wh_user_dimension;
  select is(auth_method_name,              'Widget OIDC')              from wh_user_dimension;
  select is(auth_method_description,       'None')                     from wh_user_dimension;
  select is(auth_method_external_id,       'https://oidc.widget.test') from wh_user_dimension;

  select is(user_organization_id,          'o_____widget')             from wh_user_dimension;
  select is(user_organization_name,        'Widget Inc')               from wh_user_dimension;
  select is(user_organization_description, 'None')                     from wh_user_dimension;

  select is(current_row_indicator,         'Current')                  from wh_user_dimension;

  -- insert session without full name or email
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____warren' , 'oidc__warren' , 'abc'::bytea , 'ep1'    , 's1____warren');

  select is(count(*),                      1::bigint)                  from wh_user_dimension where user_id = 'u_____warren';
  select is(user_name,                     'Warren')                   from wh_user_dimension where user_id = 'u_____warren';
  select is(user_description,              'None')                     from wh_user_dimension where user_id = 'u_____warren';

  select is(auth_account_id,               'aoa___warren')             from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_type,             'oidc auth account')        from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_name,             'warren account')           from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_description,      'Warren OIDC Account')      from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_external_id,      'sub___warren')             from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_full_name,        'None')                     from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_account_email,            'None')                     from wh_user_dimension where user_id = 'u_____warren';

  select is(auth_method_id,                'aom___widget')             from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_method_type,              'oidc auth method')         from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_method_name,              'Widget OIDC')              from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_method_description,       'None')                     from wh_user_dimension where user_id = 'u_____warren';
  select is(auth_method_external_id,       'https://oidc.widget.test') from wh_user_dimension where user_id = 'u_____warren';

  select is(user_organization_id,          'o_____widget')             from wh_user_dimension where user_id = 'u_____warren';
  select is(user_organization_name,        'Widget Inc')               from wh_user_dimension where user_id = 'u_____warren';
  select is(user_organization_description, 'None')                     from wh_user_dimension where user_id = 'u_____warren';

  select is(current_row_indicator,         'Current')                  from wh_user_dimension where user_id = 'u_____warren';

  select * from finish();
rollback;
