-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- to_sentinel tests:
--  wt_to_sentinel function

begin;
  select plan(10);

  select has_domain('wt_sentinel');
  select has_function('wt_to_sentinel', array['text']);

  select is(wt_to_sentinel('default'), u&'\fffe' || 'default' || u&'\ffff', 'create basic sentinel');
  select is(wt_to_sentinel(u&'\fffe' || 'default' || u&'\ffff'), u&'\fffe' || 'default' || u&'\ffff', 'no changes to existing sentinel');
  select is(wt_to_sentinel(''), u&'\fffe' || u&'\ffff', '0 length sentinel');
  select is(wt_to_sentinel('  '), u&'\fffe' || u&'\ffff', 'empty string becomes 0 length sentinel');
  select is(wt_to_sentinel(u&'\fffe' || u&'\ffff'), u&'\fffe' || u&'\ffff', '0 length sentinel to 0 length sentinel');
  select is(wt_to_sentinel(u&'\fffe'), u&'\fffe' || u&'\ffff', 'prefix to 0 length sentinel');
  select is(wt_to_sentinel(u&'\ffff'), u&'\fffe' || u&'\ffff', 'suffix to 0 length sentinel');

  select is(wt_to_sentinel(NULL), NULL, 'null to null');

  select * from finish();
rollback;
