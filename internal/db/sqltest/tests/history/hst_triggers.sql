-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(28);

  -- Verify the trigger functions exist and are declared properly
  select has_function('hst_on_insert');
  select volatility_is('hst_on_insert', 'volatile');
  select isnt_strict('hst_on_insert');

  select has_function('hst_on_delete');
  select volatility_is('hst_on_delete', 'volatile');
  select isnt_strict('hst_on_delete');

  select has_function('hst_on_update');
  select volatility_is('hst_on_update', 'volatile');
  select isnt_strict('hst_on_update');

  select has_trigger('iam_scope', 'hst_on_insert');
  select has_trigger('iam_scope', 'hst_on_update');
  select has_trigger('iam_scope', 'hst_on_delete');

  select is(count(a.*), count(b.*)) from iam_scope a, iam_scope_hst b;

  -- test on_delete trigger
  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p____rcolors';

  select is(upper(valid_range), null)
    from iam_scope_hst
   where public_id = 'p____rcolors';

  select ok(isempty(valid_range) = false)
    from iam_scope_hst
   where public_id = 'p____rcolors';

  delete
    from iam_scope
   where public_id = 'p____rcolors';

  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p____rcolors';

  select is(upper(valid_range), now())
    from iam_scope_hst
   where public_id = 'p____rcolors';

  select ok(isempty(valid_range) = false)
    from iam_scope_hst
   where public_id = 'p____rcolors';

  -- test on_update trigger
  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p____bcolors';

  update iam_scope
     set description = 'updated description'
   where public_id = 'p____bcolors';

  select is(count(*), 2::bigint)
    from iam_scope_hst
   where public_id = 'p____bcolors';

  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p____bcolors'
     and upper(valid_range) = now();

  update iam_scope
     set version = version + 1
   where public_id = 'p____bcolors';

  select is(count(*), 2::bigint, 'update to version column should not add a new history record')
    from iam_scope_hst
   where public_id = 'p____bcolors';

  -- test a delete happening within the same transaction as an update
  delete
    from iam_scope
   where public_id = 'p____bcolors';

  select is(count(*), 2::bigint, 'delete of scope should not add a new history record')
    from iam_scope_hst
   where public_id = 'p____bcolors';

 -- Doing an update and a delete in the same transaction produces a row in the
 -- history table with a valid_range value of 'empty'.
  select is(count(*), 1::bigint, 'an update and delete in the same transaction should result in an empty valid_range')
    from iam_scope_hst
   where public_id = 'p____bcolors'
     and isempty(valid_range);

  -- test on_insert trigger
  insert into iam_scope
    (parent_id, type, public_id, name)
  values
    ('o_____colors', 'project', 'p_______test', 'Test Color');

  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p_______test';

  select is(lower(valid_range), now())
    from iam_scope_hst
   where public_id = 'p_______test';

  select is(upper(valid_range), null)
    from iam_scope_hst
   where public_id = 'p_______test';

  select * from finish();
rollback;
