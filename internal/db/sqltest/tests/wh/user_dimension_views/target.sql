-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- target tests teh whx_user_dimension_target view.
begin;
  select plan(2);

  select is_empty($$select * from whx_user_dimension_target where user_id = 'u_____walter' and auth_account_id = 'apa___walter'$$);

  insert into wh_user_dimension
    (
      key,
      user_id,                  user_name,                       user_description,
      auth_account_id,          auth_account_type,               auth_account_name,             auth_account_description,
      auth_account_external_id, auth_account_full_name,          auth_account_email,
      auth_method_id,           auth_method_type,                auth_method_name,              auth_method_description,
      auth_method_external_id,
      user_organization_id,     user_organization_name,          user_organization_description,
      current_row_indicator,    row_effective_time,              row_expiration_time
    )
  values
    (
      'wud_____1',
      'u_____walter',           'Walter',                        'None',
      'apa___walter',           'password auth account',         'None',                        'None',
      'Not Applicable',         'Not Applicable',                'Not Applicable',
      'apm___widget',           'password auth method',          'Widget Auth Password',        'None',
      'Not Applicable',
      'o_____widget',           'Widget Inc',                    'None',
      'Expired',                '2021-07-21T11:01'::timestamptz, '2021-07-21T12:01'::timestamptz
    ),
    (
      'wud_____2',
      'u_____walter',           'Walter',                        'This is Walter',
      'apa___walter',           'password auth account',         'walter',                      'Account for Walter',
      'Not Applicable',         'Not Applicable',                'Not Applicable',
      'apm___widget',           'password auth method',          'Widget Auth Password',        'None',
      'Not Applicable',
      'o_____widget',           'Widget Inc',                    'None',
      'Current',                '2021-07-21T12:01'::timestamptz, 'infinity'::timestamptz
    );

  select is(t.*, row(
    'wud_____2',
    'u_____walter',   'Walter',                'This is Walter',
    'apa___walter',   'password auth account', 'walter',               'Account for Walter',
    'Not Applicable', 'Not Applicable',        'Not Applicable',
    'apm___widget',   'password auth method',  'Widget Auth Password', 'None',
    'Not Applicable',
    'o_____widget',   'Widget Inc',            'None'
  )::whx_user_dimension_target)
    from whx_user_dimension_target as t
   where t.user_id         = 'u_____walter'
     and t.auth_account_id = 'apa___walter';

  select * from finish();
rollback;
