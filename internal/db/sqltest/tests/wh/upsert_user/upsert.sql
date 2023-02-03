-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- upsert tests that the wh_upsert_user function will do an update when
-- an existing source wh_user_dimension exists.
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension where user_id = 'u_____walter';

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
      'u_____walter',           'Walter',                        'This is Walter',
      'apa___walter',           'password auth account',         'walter',                      'Account for Walter',
      'None',                   'None',                          'None',
      'apm___widget',           'password auth method',          'Widget Auth Password',        'None',
      'None',
      'o_____widget',           'Widget Inc',                    'None',
      'Current',                '2021-07-21T12:01'::timestamptz, 'infinity'::timestamptz
    );

  select lives_ok($$select wh_upsert_user('u_____walter', 'tok___walter')$$);

  -- upsert should insert a user_dimension
  select is(count(*), 2::bigint) from wh_user_dimension where user_id = 'u_____walter';
  select is(count(*), 1::bigint) from wh_user_dimension where user_id = 'u_____walter' and current_row_indicator = 'Current';

  select * from finish();
rollback;
