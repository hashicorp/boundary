-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- For each of these tables, swap the ordering of the
  -- columns in the index for the primary key.
  -- This helps the grants query that contains
  -- several where clauses on what is currently the second
  -- column in these indexes. By swapping the order, this
  -- will make it more likely that the query planner will
  -- choose to use the index.
  -- See: https://www.postgresql.org/docs/current/indexes-multicolumn.html

      alter table auth_oidc_managed_group_member_account
  drop constraint auth_oidc_managed_group_member_account_pkey,
  add primary key (member_id, managed_group_id);

      alter table iam_managed_group_role
  drop constraint iam_managed_group_role_pkey,
  add primary key (principal_id, role_id);

      alter table iam_group_member_user
  drop constraint iam_group_member_user_pkey,
  add primary key (member_id, group_id);

      alter table iam_group_role
  drop constraint iam_group_role_pkey,
  add primary key (principal_id, role_id);

      alter table iam_user_role
  drop constraint iam_user_role_pkey,
  add primary key (principal_id, role_id);

  analyze auth_oidc_managed_group_member_account,
          iam_managed_group_role,
          iam_group_member_user,
          iam_group_role,
          iam_user_role;
commit;
