-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(9);

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_credential_store_table_update_time');
  select volatility_is('update_credential_store_table_update_time', 'volatile');
  select isnt_strict('update_credential_store_table_update_time');
  select has_trigger('credential_vault_store', 'update_credential_store_table_update_time');
  select has_trigger('credential_static_store', 'update_credential_store_table_update_time');
  select has_index('credential_store', 'credential_store_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('credential_store', 'credential_store_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test that the trigger that sets the create_time of the base table
  -- when an insert into a subtype table happens works, we check that the
  -- create time of the entries in both tables match
  prepare credential_store_create_time as select create_time from credential_store where public_id='cvs__bcolors';
  prepare credential_vault_store_create_time as select create_time from credential_vault_store where public_id='cvs__bcolors';
  select results_eq('credential_store_create_time','credential_vault_store_create_time');
  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing creds and check that the base table
  -- entry has the same update_time as the subtype one.
  update credential_vault_store set name='blue black vault store' where public_id='cvs__bcolors';
  prepare credential_store_update_time as select update_time from credential_store where public_id='cvs__bcolors';
  prepare credential_vault_store_update_time as select update_time from credential_vault_store where public_id='cvs__bcolors';
  select results_eq('credential_store_update_time','credential_vault_store_update_time');

  select * from finish();

rollback;
