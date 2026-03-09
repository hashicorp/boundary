-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(16);

  -- Verify the trigger functions exist and are declared properly
  select has_function('insert_credential_library_history_subtype');
  select volatility_is('insert_credential_library_history_subtype', 'volatile');
  select isnt_strict('insert_credential_library_history_subtype');

  select has_function('delete_credential_library_history_subtype');
  select volatility_is('delete_credential_library_history_subtype', 'volatile');
  select isnt_strict('delete_credential_library_history_subtype');

  select has_trigger('credential_vault_generic_library_hst', 'insert_credential_library_history_subtype');
  select has_trigger('credential_vault_generic_library_hst', 'delete_credential_library_history_subtype');
  select fk_ok('credential_vault_generic_library_hst', 'history_id', 'credential_library_history_base' , 'history_id');

  select has_trigger('credential_vault_ssh_cert_library_hst', 'insert_credential_library_history_subtype');
  select has_trigger('credential_vault_ssh_cert_library_hst', 'delete_credential_library_history_subtype');
  select fk_ok('credential_vault_ssh_cert_library_hst', 'history_id', 'credential_library_history_base' , 'history_id');

  select has_trigger('credential_vault_ldap_library_hst', 'insert_credential_library_history_subtype');
  select has_trigger('credential_vault_ldap_library_hst', 'delete_credential_library_history_subtype');
  select fk_ok('credential_vault_ldap_library_hst', 'history_id', 'credential_library_history_base' , 'history_id');

  select results_eq(
    'select '
    '(select count(*) from credential_vault_generic_library_hst) + '
    '(select count(*) from credential_vault_ssh_cert_library_hst) + '
    '(select count(*) from credential_vault_ldap_library_hst)',
    'select count(*) from credential_library_history_base'
  );

  select * from finish();
rollback;


