-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(9);

  -- Verify the trigger functions exist and are declared properly
  select has_function('update_host_catalog_table_update_time');
  select volatility_is('update_host_catalog_table_update_time', 'volatile');
  select isnt_strict('update_host_catalog_table_update_time');
  select has_trigger('static_host_catalog', 'update_host_catalog_table_update_time');
  select has_trigger('host_plugin_catalog', 'update_host_catalog_table_update_time');
  select has_index('host_catalog', 'host_catalog_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('host_catalog', 'host_catalog_update_time_public_id_idx', array['update_time', 'public_id']);

  -- To test that the trigger that sets the create_time of the base table
  -- when an insert into a subtype table happens works, we check that the
  -- create time of the entries in both tables match
  prepare host_catalog_create_time as select create_time from host_catalog where public_id='hc__st_____b';
  prepare static_host_catalog_create_time as select create_time from static_host_catalog where public_id='hc__st_____b';
  select results_eq('host_catalog_create_time','static_host_catalog_create_time');
  -- To test the trigger that updates the update_time of the base table,
  -- we update one of the existing catalog and check that the base table
  -- entry has the same update_time as the subtype one.
  update static_host_catalog set name='blue black static host catalog' where public_id='hc__st_____b';
  prepare host_catalog_update_time as select update_time from host_catalog where public_id='hc__st_____b';
  prepare static_host_catalog_update_time as select update_time from static_host_catalog where public_id='hc__st_____b';
  select results_eq('host_catalog_update_time','static_host_catalog_update_time');

  select * from finish();

rollback;
