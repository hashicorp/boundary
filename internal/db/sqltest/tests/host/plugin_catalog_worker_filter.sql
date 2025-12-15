-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(18);
  select wtt_load('widgets', 'iam', 'hosts');
  
  -- Check plugin host catalog that doesn't have worker_filter set.
  select is(worker_filter, null::wt_bexprfilter) from host_plugin_catalog
    where public_id = 'c___ws-plghcl';
  select is(worker_filter, null::wt_bexprfilter) from host_plugin_catalog_with_secret
    where public_id = 'c___ws-plghcl';
  select is(count(*), 1::bigint) from host_plugin_catalog_hst
    where public_id = 'c___ws-plghcl';
  select is(worker_filter, null::wt_bexprfilter) from host_plugin_catalog_hst
    where public_id = 'c___ws-plghcl';

  -- Test we can add a worker_filter to a plugin host catalog that doesn't have
  -- one.
  prepare add_worker_filter as
    update host_plugin_catalog
      set worker_filter = '"add_worker_filter" in "/tags/type"'
      where public_id = 'c___ws-plghcl';
  select lives_ok('add_worker_filter');

  select is(worker_filter, '"add_worker_filter" in "/tags/type"') from host_plugin_catalog
    where public_id = 'c___ws-plghcl';
  select is(worker_filter, '"add_worker_filter" in "/tags/type"') from host_plugin_catalog_with_secret
    where public_id = 'c___ws-plghcl';
  select is(count(*), 2::bigint) from host_plugin_catalog_hst
    where public_id = 'c___ws-plghcl';
  select results_eq('select worker_filter from host_plugin_catalog_hst where public_id = ''c___ws-plghcl''',
    ARRAY[null::wt_bexprfilter, '"add_worker_filter" in "/tags/type"'::wt_bexprfilter]);

  -- Check plugin host catalog that already has a worker_filter set.
  select is(worker_filter, '"test" in "/tags/type"') from host_plugin_catalog
    where public_id = 'c___wb-plghcl';
  select is(worker_filter, '"test" in "/tags/type"') from host_plugin_catalog_with_secret
    where public_id = 'c___wb-plghcl';
  select is(count(*), 1::bigint) from host_plugin_catalog_hst
    where public_id = 'c___wb-plghcl';
  select is(worker_filter, '"test" in "/tags/type"') from host_plugin_catalog_hst
    where public_id = 'c___wb-plghcl';

  -- Test we can mutate worker_filter on a plugin host catalog.
  prepare update_worker_filter as
    update host_plugin_catalog
      set worker_filter = '"update_worker_filter" in "/tags/type"'
      where public_id = 'c___wb-plghcl';
  select lives_ok('update_worker_filter');

  select is(worker_filter, '"update_worker_filter" in "/tags/type"') from host_plugin_catalog
    where public_id = 'c___wb-plghcl';
  select is(worker_filter, '"update_worker_filter" in "/tags/type"') from host_plugin_catalog_with_secret
    where public_id = 'c___wb-plghcl';
  select is(count(*), 2::bigint) from host_plugin_catalog_hst
    where public_id = 'c___wb-plghcl';
  select results_eq('select worker_filter from host_plugin_catalog_hst where public_id = ''c___wb-plghcl''',
    ARRAY['"test" in "/tags/type"'::wt_bexprfilter, '"update_worker_filter" in "/tags/type"'::wt_bexprfilter]);

  select * from finish();
rollback;
