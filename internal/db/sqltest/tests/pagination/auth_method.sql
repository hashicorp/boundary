-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(17);
  -- load to test with ldap auth method
  select wtt_load('widgets', 'iam', 'kms', 'auth');

  -- validate the setup data
  select is(count(*), 1::bigint) from auth_ldap_account where public_id = 'ala___walter';
  select is(count(*), 1::bigint) from auth_account where public_id = 'ala___walter';

  -- validate the insert triggers
  prepare insert_ldap_account as
      insert into auth_ldap_account
          (auth_method_id,   public_id,     login_name)
      values
          ('alm___widget',   'ala___tania', 'tania');
  select lives_ok('insert_ldap_account');

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_auth_method_table_update_time');
  select volatility_is('update_auth_method_table_update_time', 'volatile');
  select isnt_strict('update_auth_method_table_update_time');
  select has_trigger('auth_ldap_method', 'update_auth_method_table_update_time');
  select has_trigger('auth_oidc_method', 'update_auth_method_table_update_time');
  select has_trigger('auth_password_method', 'update_auth_method_table_update_time');
  select has_trigger('auth_password_method', 'insert_auth_method_password_subtype');
  select has_trigger('auth_ldap_method', 'update_auth_method_table_is_active_public_state');
  select has_trigger('auth_oidc_method', 'update_auth_method_table_is_active_public_state');
  select has_index('auth_method', 'auth_method_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_method', 'auth_method_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test that the trigger that sets the create_time of the base table
  -- when an insert into a subtype table happens works, we check that the
  -- create time of the entries in both tables match
  prepare auth_method_create_time as select create_time from auth_method where public_id='apm___colors';
  prepare auth_password_method_create_time as select create_time from auth_password_method where public_id='apm___colors';
  select results_eq('auth_method_create_time','auth_password_method_create_time');

  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing subtypes and check that the base table
  -- entry has the same update_time as the subtype one.
  update auth_password_method set name='blue black am' where public_id='apm___colors';
  prepare auth_method_update_time as select update_time from auth_method where public_id='apm___colors';
  prepare auth_password_method_update_time as select update_time from auth_password_method where public_id='apm___colors';
  select results_eq('auth_method_update_time','auth_password_method_update_time');

  -- To test the trigger that updates the is_active_public_state of the base table,
  -- we set one of the existing subtypes states to 'active-public' and check that the base table
  -- entry has updated its column to true.
  update auth_ldap_method set state='active-public' where public_id='ala___tania';
  prepare auth_method_is_active_public_state as select is_active_public_state from auth_method where public_id='ala___tania';
  prepare auth_ldap_method_state_is_active_public_state as select state = 'active-public' from auth_ldap_method where public_id='ala___tania';
  select results_eq('auth_method_is_active_public_state','auth_ldap_method_state_is_active_public_state');

  select * from finish();

rollback;