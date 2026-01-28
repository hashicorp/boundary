-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- is_sentinel tests:
--  wt_is_sentinel function

begin;
  select plan(10);

  select has_domain('wt_sentinel');
  select has_function('wt_is_sentinel', array['text']);

  select ok(wt_is_sentinel(u&'\fffe' || 'default' || u&'\ffff'), 'basic sentinel');
  select ok(wt_is_sentinel(u&'\fffe' || u&'\ffff'), '0 length sentinel');
  select ok(wt_is_sentinel(u&'\fffe' || ' ' || u&'\ffff'), 'empty sentinel');

  select ok(not wt_is_sentinel('default'), 'a word is not a sentinel');
  select ok(not wt_is_sentinel(''), '0 length string is not a sentinel');
  select ok(not wt_is_sentinel(' '), 'empty string is not a sentinel');
  select ok(not wt_is_sentinel(u&'\fffe' || 'default'), 'missing suffix of ffff is not a sentinel');
  select ok(not wt_is_sentinel('default' || u&'\ffff'), 'missing prefix of fffe is not a sentinel');

  select * from finish();
rollback;
