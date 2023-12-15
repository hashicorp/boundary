-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(9);

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_auth_method_table_update_time');
  select volatility_is('update_auth_method_table_update_time', 'volatile');
  select isnt_strict('update_auth_method_table_update_time');
  select has_trigger('auth_ldap_method', 'update_auth_method_table_update_time');
  select has_trigger('auth_oidc_method', 'update_auth_method_table_update_time');
  select has_trigger('auth_password_method', 'update_auth_method_table_update_time');
  select has_index('auth_method', 'auth_method_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('auth_method', 'auth_method_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test that the trigger that sets the create_time of the base table
  -- when an insert into a subtype table happens works, we check that the
  -- create time of the entries in both tables match
  prepare auth_method_create_time as select create_time from auth_method where public_id='apm___colors';
  prepare auth_ldap_method_create_time as select create_time from auth_ldap_method where public_id='apm___colors';
  select results_eq('auth_method_create_time','auth_ldap_method_create_time');
  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing creds and check that the base table
  -- entry has the same update_time as the subtype one.
  update auth_ldap_method set name='blue black vault store' where public_id='apm___colors';
  prepare auth_method_update_time as select update_time from auth_method where public_id='apm___colors';
  prepare auth_ldap_method_update_time as select update_time from auth_ldap_method where public_id='apm___colors';
  select results_eq('auth_method_update_time','auth_ldap_method_update_time');

  select * from finish();

rollback;