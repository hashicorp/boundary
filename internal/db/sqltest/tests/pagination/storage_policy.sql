-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select has_index(
    'policy_storage_policy',
    'policy_storage_policy_create_time_public_id_idx',
    array['create_time', 'public_id']
  );
  select has_index(
    'policy_storage_policy',
    'policy_storage_policy_update_time_public_id_idx',
    array['update_time', 'public_id']
  );

  select * from finish();

rollback;
