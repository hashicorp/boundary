-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table job_run
    add column retries_count int not null default 0
        constraint retries_count_can_not_be_negative
          check(retries_count >= 0);

commit;
