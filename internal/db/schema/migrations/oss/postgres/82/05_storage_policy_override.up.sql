-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table policy_storage_policy
    alter column retain_for_days_overridable set default false,
    alter column delete_after_days_overridable set default false;

commit;
