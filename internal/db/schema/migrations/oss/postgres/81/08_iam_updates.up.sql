-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index iam_role_create_time_public_id_idx
      on iam_role (create_time desc, public_id desc);
  create index iam_role_update_time_public_id_idx
      on iam_role (update_time desc, public_id desc);
  analyze iam_role;

  create index iam_user_create_time_public_id_idx
      on iam_user (create_time desc, public_id desc);
  create index iam_user_update_time_public_id_idx
      on iam_user (update_time desc, public_id desc);
  analyze iam_user;

  create index iam_group_create_time_public_id_idx
      on iam_group (create_time desc, public_id desc);
  create index iam_group_update_time_public_id_idx
      on iam_group (update_time desc, public_id desc);
  analyze iam_group;

  create index iam_scope_create_time_public_id_idx
      on iam_scope (create_time desc, public_id desc);
  create index iam_scope_update_time_public_id_idx
      on iam_scope (update_time desc, public_id desc);
  analyze iam_scope;

commit;
