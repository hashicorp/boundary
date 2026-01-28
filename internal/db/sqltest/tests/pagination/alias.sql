-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select has_index('alias_target', 'alias_target_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('alias_target', 'alias_target_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;