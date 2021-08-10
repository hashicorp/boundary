-- password_auth_new_session tests the wh_user_dimesion when
-- a new session is created using the password auth method.
begin;
  select plan(17);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension;

  -- insert first session, should result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*),                      1::bigint)               from wh_user_dimension;
  select is(user_id,                       'u_____walter')          from wh_user_dimension;
  select is(user_name,                     'Walter')                from wh_user_dimension;
  select is(user_description,              'None')                  from wh_user_dimension;

  select is(auth_account_id,               'apa___walter')          from wh_user_dimension;
  select is(auth_account_type,             'password auth account') from wh_user_dimension;
  select is(auth_account_name,             'None')                  from wh_user_dimension;
  select is(auth_account_description,      'None')                  from wh_user_dimension;

  select is(auth_method_id,                'apm___widget')          from wh_user_dimension;
  select is(auth_method_type,              'password auth method')  from wh_user_dimension;
  select is(auth_method_name,              'Widget Auth Password')  from wh_user_dimension;
  select is(auth_method_description,       'None')                  from wh_user_dimension;

  select is(user_organization_id,          'o_____widget')          from wh_user_dimension;
  select is(user_organization_name,        'Widget Inc')            from wh_user_dimension;
  select is(user_organization_description, 'None')                  from wh_user_dimension;

  select is(current_row_indicator,         'Current')               from wh_user_dimension;

  select * from finish();
rollback;
