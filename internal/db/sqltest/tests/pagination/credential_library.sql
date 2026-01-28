-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(12);

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_credential_library_table_update_time');
  select volatility_is('update_credential_library_table_update_time', 'volatile');
  select isnt_strict('update_credential_library_table_update_time');

  select has_function('update_credential_vault_library_table_update_time');
  select volatility_is('update_credential_vault_library_table_update_time', 'volatile');
  select isnt_strict('update_credential_vault_library_table_update_time');
  select has_trigger('credential_vault_generic_library', 'update_credential_vault_library_table_update_time');
  select has_trigger('credential_vault_ssh_cert_library', 'update_credential_vault_library_table_update_time');
  select has_index('credential_library', 'credential_library_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('credential_library', 'credential_library_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test that the trigger that sets the create_time of the base table
  -- when an insert into a subtype table happens works, we check that the
  -- create time of the entries in both tables match
  prepare credential_library_create_time as select create_time from credential_library where public_id='cvl_______b1';
  prepare credential_vault_library_create_time as select create_time from credential_vault_generic_library where public_id='cvl_______b1';
  select results_eq('credential_library_create_time','credential_vault_library_create_time');
  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing creds and check that the base table
  -- entry has the same update_time as the subtype one.
  update credential_vault_generic_library set name='blue black vault library' where public_id='cvl_______b1';
  prepare credential_library_update_time as select update_time from credential_library where public_id='cvl_______b1';
  prepare credential_vault_library_update_time as select update_time from credential_vault_generic_library where public_id='cvl_______b1';
  select results_eq('credential_library_update_time','credential_vault_library_update_time');

  select * from finish();

rollback;
