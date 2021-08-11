-- source tests teh whx_user_dimension_source view.
begin;
  select plan(4);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- auth_password_account
  select is(s.*, row(
    'u_____walter', 'Walter',                'None',
    'apa___walter', 'password auth account', 'None',                 'None',
    'apm___widget', 'password auth method',  'Widget Auth Password', 'None',
    'o_____widget', 'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'apa___walter';

  select is(s.*, row(
    'u_____walter', 'Walter',                'None',
    'apa1__walter', 'password auth account', 'None',                   'None',
    'apm1__widget', 'password auth method',  'Widget Auth Password 1', 'None',
    'o_____widget', 'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'apa1__walter';

  select is(s.*, row(
    'u_____warren', 'Warren',                'None',
    'apa___warren', 'password auth account', 'None',                 'None',
    'apm___widget', 'password auth method',  'Widget Auth Password', 'None',
    'o_____widget', 'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____warren'
     and s.auth_account_id = 'apa___warren';

  -- auth_oidc_account
  select is(s.*, row(
    'u_____walter', 'Walter',                'None',
    'aoa___walter', 'password auth account', 'None', 'None',
    'aom___widget', 'password auth method',  'None', 'None',
    'o_____widget', 'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'aoa___walter';

  select * from finish();
rollback;
