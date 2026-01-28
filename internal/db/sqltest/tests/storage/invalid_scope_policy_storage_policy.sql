-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);
  select wtt_load('widgets', 'iam');

  insert into iam_scope
    (parent_id, type, public_id, name)
  values
    ('global', 'org', 'o_____widget2', 'Widget 2 Inc');

  -- insert storage policy.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', -1, 0, 'Test Storage Policy', 'This is a test storage policy');

  -- invalid scope_policy_storage_policy: scope is not global and does not match
  -- the storage policy scope.
  select throws_ok($$
    insert into scope_policy_storage_policy
      (scope_id, storage_policy_id)
    values
      ('o_____widget2', 'pst____policy')
  $$, 'invalid scope_id for scope_storage_policy association');

  select is(count(*), 0::bigint) from scope_policy_storage_policy
  where
    scope_id = 'o_____widget2' and
    storage_policy_id = 'pst____policy';

  delete from iam_scope where public_id = 'o_____widget2';
rollback;
