-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select has_index('iam_user', 'iam_user_create_time_public_id_idx', array['create_time', 'public_id']);
  select has_index('iam_user', 'iam_user_update_time_public_id_idx', array['update_time', 'public_id']);

  select * from finish();

rollback;