-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- replaces constraints from internal/db/schema/migrations/postgres/82/01_storage_policies.up.sql
  alter table policy 
    drop constraint policy_scope_id_fkey;
  alter table policy
    add constraint policy_scope_id_fkey
    foreign key (scope_id)
      references iam_scope(public_id)
      on delete cascade
      on update cascade;

  alter table policy_storage_policy 
    drop constraint policy_storage_policy_scope_id_fkey;
  alter table policy_storage_policy
    add constraint policy_storage_policy_scope_id_fkey
    foreign key (scope_id)
      references iam_scope(public_id)
      on delete cascade
      on update cascade;

commit;
