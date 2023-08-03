-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(1);

  select has_index('target_deleted',
                   'target_deleted_time_idx',
                   'delete_time',
                   'index for cleanup table target_deleted missing');

  select * from finish();
rollback;
