-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(3);
  select wtt_load('widgets', 'iam');

  -- insert storage policy.
  insert into storage_policy
    (public_id,      scope_id,       retention_days, name,      description)
  values
    ('sp____policy', 'o_____widget', -1, 'Test Storage Policy', 'This is a test storage policy');

  -- 'policy' abstract table should now have a new association due to insert
  -- above.
  select is(count(*), 1::bigint) from policy
  where
  public_id = 'sp____policy' and
  scope_id = 'o_____widget';

  -- update a storage policy.
  update storage_policy set retention_days = 1
  where
  public_id = 'sp____policy' and
  scope_id = 'o_____widget';

  select is(retention_days, 1::integer) from storage_policy
  where
  public_id = 'sp____policy' and
  scope_id = 'o_____widget';

  -- delete a storage policy.
  delete from storage_policy
  where
  public_id = 'sp____policy' and
  scope_id = 'o_____widget';

  -- row should be deleted from 'policy' abstract table.
  select is(count(*), 0::bigint) from policy
  where
  public_id = 'sp____policy' and
  scope_id = 'o_____widget';
rollback;