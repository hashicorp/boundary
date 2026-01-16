-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- source tests the whx_user_dimension_source view.
begin;
  select plan(7);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- auth_password_account
  select is(s.*, row(
    'u_____walter',   'Walter',                'None',
    'apa___walter',   'password auth account', 'None',                 'None',
    'Not Applicable', 'Not Applicable',        'Not Applicable',
    'apm___widget',   'password auth method',  'Widget Auth Password', 'None',
    'Not Applicable',
    'o_____widget',   'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'apa___walter';

  select is(s.*, row(
    'u_____walter',   'Walter',                'None',
    'apa1__walter',   'password auth account', 'None',                   'None',
    'Not Applicable', 'Not Applicable',        'Not Applicable',
    'apm1__widget',   'password auth method',  'Widget Auth Password 1', 'None',
    'Not Applicable',
    'o_____widget',   'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'apa1__walter';

  select is(s.*, row(
    'u_____warren',   'Warren',                'None',
    'apa___warren',   'password auth account', 'None',                 'None',
    'Not Applicable', 'Not Applicable',        'Not Applicable',
    'apm___widget',   'password auth method',  'Widget Auth Password', 'None',
    'Not Applicable',
    'o_____widget',   'Widget Inc',            'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____warren'
     and s.auth_account_id = 'apa___warren';

  -- auth_oidc_account
  select is(s.*, row(
    'u_____walter',             'Walter',            'None',
    'aoa___walter',             'oidc auth account', 'walter account',     'Walter OIDC Account',
    'sub___walter',             'Walter',            'walter@widget.test',
    'aom___widget',             'oidc auth method',  'Widget OIDC',        'None',
    'https://oidc.widget.test',
    'o_____widget',             'Widget Inc',        'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'aoa___walter';

  select is(s.*, row(
    'u_____warren',             'Warren',            'None',
    'aoa___warren',             'oidc auth account', 'warren account', 'Warren OIDC Account',
    'sub___warren',             'None',              'None',
    'aom___widget',             'oidc auth method',  'Widget OIDC',    'None',
    'https://oidc.widget.test',
    'o_____widget',             'Widget Inc',        'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____warren'
     and s.auth_account_id = 'aoa___warren';

-- auth_ldap_account
  select is(s.*, row(
    'u_____walter',             'Walter',            'None',
    'ala___walter',             'ldap auth account', 'walter account',     'Walter LDAP Account',
    'walter',                   'Walter',            'walter@widget.test',
    'alm___widget',             'ldap auth method',  'Widget LDAP',        'None',
    'Not Applicable',
    'o_____widget',             'Widget Inc',        'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____walter'
     and s.auth_account_id = 'ala___walter';

  select is(s.*, row(
    'u_____warren',             'Warren',            'None',
    'ala___warren',             'ldap auth account', 'warren account', 'Warren LDAP Account',
    'warren',                   'None',              'None',
    'alm___widget',             'ldap auth method',  'Widget LDAP',    'None',
    'Not Applicable',
    'o_____widget',             'Widget Inc',        'None'
  )::whx_user_dimension_source)
    from whx_user_dimension_source as s
   where s.user_id         = 'u_____warren'
     and s.auth_account_id = 'ala___warren';

  select * from finish();
rollback;
