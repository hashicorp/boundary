-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(14);
  select wtt_load('widgets', 'iam');

  -- insert invalid storage policy: delete_after_days is lower than
  -- retain_for_days.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy', 'o_____widget', 5, 1, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'new row for relation "policy_storage_policy" violates check constraint "delete_after_days_greater_or_equal_than_retain_for_days"');

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert invalid storage policy: use project-level scope.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy', 'p____bwidget', -1, 0, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'invalid scope type for storage policy creation');

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'p____bwidget';

  -- insert invalid storage policy: negative delete_after_days.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy', 'o_____widget', -1, -1, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'deletion period set on infinite retention period policy');

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert valid storage policy to test using same policy name on a given scope.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', -1, 0, 'Test Storage Policy', 'This is a test storage policy');

  -- since we already have a 'Test Storage Policy', this should fail.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy2', 'o_____widget', -1, 0, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'duplicate key value violates unique constraint "policy_storage_policy_scope_id_name_uq"');

  -- cleanup so that we can run more tests with the same insert query below.
  delete from policy_storage_policy where public_id = 'pst____policy';

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert invalid storage policy: retain_for_days and delete_after_days are
  -- both zero.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy', 'o_____widget', 0, 0, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'retain_for_days and delete_after_days are both zero');

  -- insert valid storage policy to test update with both retain_for_days and
  -- delete_after_days set to zero.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', -1, 0, 'Test Storage Policy', 'This is a test storage policy');

  select throws_ok($$
    update policy_storage_policy set (retain_for_days, delete_after_days) = (0, 0)
      where public_id = 'pst____policy'
  $$, 'retain_for_days and delete_after_days are both zero');

  -- cleanup so that we can run more tests with the same insert query below.
  delete from policy_storage_policy where public_id = 'pst____policy';

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert invalid storage policy: infinite retention policy (-1) with a
  -- deletion policy.
  select throws_ok($$
    insert into policy_storage_policy
      (public_id, scope_id, retain_for_days, delete_after_days, name, description)
    values
      ('pst____policy', 'o_____widget', -1, 5, 'Test Storage Policy', 'This is a test storage policy')
  $$, 'deletion period set on infinite retention period policy');

  -- 'policy' abstract table should not have a new association.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert valid storage policy to test updating infinite retention policy (-1)
  -- with a deletion policy present.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', 5, 5, 'Test Storage Policy', 'This is a test storage policy');

  select throws_ok($$
    update policy_storage_policy set retain_for_days = -1
      where public_id = 'pst____policy'
  $$, 'deletion period set on infinite retention period policy');

  -- cleanup so that we can run more tests with the same insert query below.
  delete from policy_storage_policy where public_id = 'pst____policy';
rollback;
