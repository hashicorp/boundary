-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(8);

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_target_table_update_time');
  select volatility_is('update_target_table_update_time', 'volatile');
  select isnt_strict('update_target_table_update_time');
  select has_trigger('target_ssh', 'update_target_table_update_time');
  select has_trigger('target_tcp', 'update_target_table_update_time');
  select has_index('target', 'target_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('target', 'target_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing targets and check that the base table
  -- entry has the same update_time as the subtype one.
  update target_tcp set name='Blue black color target' where public_id='t_________cb';
  prepare target_update_time as select update_time from target where public_id='t_________cb';
  prepare target_tcp_update_time as select update_time from target_tcp where public_id='t_________cb';
  select results_eq('target_update_time','target_tcp_update_time');

  select * from finish();

rollback;
