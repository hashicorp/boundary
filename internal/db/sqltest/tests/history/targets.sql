-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(10);

  -- Verify the trigger functions exist and are declared properly
  select has_function('insert_target_history_subtype');
  select volatility_is('insert_target_history_subtype', 'volatile');
  select isnt_strict('insert_target_history_subtype');

  select has_function('delete_target_history_subtype');
  select volatility_is('delete_target_history_subtype', 'volatile');
  select isnt_strict('delete_target_history_subtype');

  select has_trigger('target_rdp_hst', 'hst_after_delete');
  select has_trigger('target_rdp_hst', 'hst_before_insert');
  select fk_ok('target_rdp_hst', 'history_id', 'target_history_base' , 'history_id');

  select results_eq(
    'select '
      '(select count(*) from target_rdp_hst) + '
      '(select count(*) from target_ssh_hst)',
    'select count(*) from target_history_base'
  );

  select * from finish();
rollback;