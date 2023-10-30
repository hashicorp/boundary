-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add new indexes for the create time and update time queries.
  create index iam_role_create_time_public_id_idx
      on iam_role (create_time desc, public_id asc);
  create index iam_role_update_time_public_id_idx
      on iam_role (update_time desc, public_id asc);

  analyze iam_role;

commit;