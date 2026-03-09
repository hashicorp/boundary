-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- upsert tests that the wh_upsert_user function will do an update when
-- an existing source wh_user_dimension exists.
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension where user_id = 'u_____wilson';

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
      'u_____wilson',           'Wilson',                        'This is Wilson',
      'apa___wilson',           'password auth account',         'wilson',                      'Account for Wilson',
      'None',                   'None',                          'None',
      'apm___widget',           'password auth method',          'Widget Auth Password',        'None',
      'None',
      'o_____widget',           'Widget Inc',                    'None',
      'Current',                '2021-07-21T12:01'::timestamptz, 'infinity'::timestamptz
    );

  select lives_ok($$select wh_upsert_user('tok___wilson')$$);

  -- upsert should insert a user_dimension
  select is(count(*), 2::bigint) from wh_user_dimension where user_id = 'u_____wilson';
  select is(count(*), 1::bigint) from wh_user_dimension where user_id = 'u_____wilson' and current_row_indicator = 'Current';

  select * from finish();
rollback;
