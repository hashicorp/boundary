-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(5);
  select wtt_load('widgets', 'iam');

  -- insert storage policy.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy', 'o_____widget', 5, 10, 'Test Storage Policy', 'This is a test storage policy');

  -- 'policy' abstract table should now have a new association due to insert
  -- above.
  select is(count(*), 1::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- update a storage policy's retain_for_days
  update policy_storage_policy set retain_for_days = 1
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  select is(retain_for_days, 1::integer) from policy_storage_policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- update a storage policy's delete_after_days
  update policy_storage_policy set delete_after_days = 20
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  select is(delete_after_days, 20::integer) from policy_storage_policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- delete a storage policy.
  delete from policy_storage_policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- row should be deleted from 'policy' abstract table.
  select is(count(*), 0::bigint) from policy
  where
    public_id = 'pst____policy' and
    scope_id = 'o_____widget';

  -- delete_after_days is less than retain_for_days, however it is 0, which is a
  -- valid carve-out on delete_after_days_greater_or_equal_than_retain_for_days.
  insert into policy_storage_policy
    (public_id, scope_id, retain_for_days, delete_after_days, name, description)
  values
    ('pst____policy2', 'o_____widget', 5, 0, 'Test Storage Policy 2', 'This is a test storage policy');

  select is(count(*), 1::bigint) from policy
  where
    public_id = 'pst____policy2' and
    scope_id = 'o_____widget';
rollback;