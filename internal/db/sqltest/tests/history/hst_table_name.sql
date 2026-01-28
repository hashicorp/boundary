-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(5);

  -- Verify the function exists and is declared properly
  select has_function('hst_table_name', array['name', 'name']);
  select volatility_is('hst_table_name', 'immutable');
  select is_strict('hst_table_name');

  select is(hst_table_name('public', 'iam_scope'), 'public.iam_scope_hst');
  select is(hst_table_name(null, null), null);

  select * from finish();
rollback;
