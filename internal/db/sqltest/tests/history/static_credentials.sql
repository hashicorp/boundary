-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(19);

  -- Verify the trigger functions exist and are declared properly
  select has_function('insert_credential_static_history_subtype');
  select volatility_is('insert_credential_static_history_subtype', 'volatile');
  select isnt_strict('insert_credential_static_history_subtype');

  select has_function('delete_credential_static_history_subtype');
  select volatility_is('delete_credential_static_history_subtype', 'volatile');
  select isnt_strict('delete_credential_static_history_subtype');

  select has_trigger('credential_static_json_credential_hst', 'insert_credential_static_history_subtype');
  select has_trigger('credential_static_json_credential_hst', 'delete_credential_static_history_subtype');
  select fk_ok('credential_static_json_credential_hst', 'history_id', 'credential_static_history_base' , 'history_id');

  select has_trigger('credential_static_username_password_credential_hst', 'insert_credential_static_history_subtype');
  select has_trigger('credential_static_username_password_credential_hst', 'delete_credential_static_history_subtype');
  select fk_ok('credential_static_username_password_credential_hst', 'history_id', 'credential_static_history_base' , 'history_id');

  select has_trigger('credential_static_username_password_domain_credential_hst', 'insert_credential_static_history_subtype');
  select has_trigger('credential_static_username_password_domain_credential_hst', 'delete_credential_static_history_subtype');
  select fk_ok('credential_static_username_password_domain_credential_hst', 'history_id', 'credential_static_history_base' , 'history_id');

  select has_trigger('credential_static_ssh_private_key_credential_hst', 'insert_credential_static_history_subtype');
  select has_trigger('credential_static_ssh_private_key_credential_hst', 'delete_credential_static_history_subtype');
  select fk_ok('credential_static_ssh_private_key_credential_hst', 'history_id', 'credential_static_history_base' , 'history_id');

  select results_eq(
    'select '
    '(select count(*) from credential_static_json_credential_hst) + '
    '(select count(*) from credential_static_username_password_credential_hst) + '
    '(select count(*) from credential_static_username_password_domain_credential_hst) + '
    '(select count(*) from credential_static_ssh_private_key_credential_hst)',
    'select count(*) from credential_static_history_base'
  );

  select * from finish();
rollback;

