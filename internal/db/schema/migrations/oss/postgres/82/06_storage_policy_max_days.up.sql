-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table policy_storage_policy
    add constraint delete_after_days_less_than_100_years
      check(delete_after_days <= 36525),
    add constraint retain_for_days_less_than_100_years
      check(retain_for_days <= 36525);

commit;
