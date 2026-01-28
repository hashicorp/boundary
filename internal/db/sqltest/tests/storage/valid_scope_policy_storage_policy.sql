-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);
  select wtt_load('widgets', 'iam');

  -- insert storage policy.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', -1, 0, 'Test Storage Policy', 'This is a test storage policy');

  -- 'policy' abstract table should now have a new association due to insert
  -- above.
  select is(count(*), 1::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- insert into scope_policy_storage_policy association table.
  insert into scope_policy_storage_policy
    (scope_id, storage_policy_id)
  values
    ('o_____widget', 'pst____policy');

  select is(count(*), 1::bigint) from scope_policy_storage_policy
  where
    scope_id = 'o_____widget' and
    storage_policy_id = 'pst____policy';

  -- Reset to allow for next test.
  delete from scope_policy_storage_policy
  where
    scope_id = 'o_____widget' and
    storage_policy_id = 'pst____policy';

  -- A `global` storage policy should be able to be associated with any scope
  -- insert storage policy.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy2', 'global', -1, 0, 'Test Storage Policy 2', 'This is a test storage policy');

  insert into scope_policy_storage_policy
    (scope_id, storage_policy_id)
  values
    ('global', 'pst____policy2');

  insert into scope_policy_storage_policy
    (scope_id, storage_policy_id)
  values
    ('o_____widget', 'pst____policy2');
rollback;
