-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(15);

  -- Verify the trigger functions exist and are declared properly
  select has_function('insert_host_catalog_history_subtype');
  select volatility_is('insert_host_catalog_history_subtype', 'volatile');
  select isnt_strict('insert_host_catalog_history_subtype');

  select has_function('delete_host_catalog_history_subtype');
  select volatility_is('delete_host_catalog_history_subtype', 'volatile');
  select isnt_strict('delete_host_catalog_history_subtype');

  select has_trigger('static_host_catalog_hst', 'insert_host_catalog_history_subtype');
  select has_trigger('static_host_catalog_hst', 'delete_host_catalog_history_subtype');
  select fk_ok('static_host_catalog_hst', 'history_id', 'host_catalog_history_base' , 'history_id');

  select has_trigger('host_plugin_catalog_hst', 'insert_host_catalog_history_subtype');
  select has_trigger('host_plugin_catalog_hst', 'delete_host_catalog_history_subtype');
  select fk_ok('host_plugin_catalog_hst', 'history_id', 'host_catalog_history_base' , 'history_id');

  select is(count(*), 1::bigint) from no_host_catalog_history;
  select fk_ok('no_host_catalog_history', 'history_id', 'host_catalog_history_base' , 'history_id');

  select results_eq(
    'select '
    '(select count(*) from static_host_catalog_hst) + '
    '(select count(*) from host_plugin_catalog_hst) + '
    '(select count(*) from no_host_catalog_history)',
    'select count(*) from host_catalog_history_base'
  );

  select * from finish();
rollback;
