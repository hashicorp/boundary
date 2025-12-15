-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- Boundary's design on removing entries from job_run has changed from having a
-- job that periodically cleans the table to a design where the scheduler
-- handles this by itself if the job is successful. It is possible that some
-- entries are left in the table with this change (eg: Boundary is stopped after
-- some jobs run but before the cleaner job runs).
--
-- These entries would forever be stored, so this migration cleans them to
-- ensure no dangling rows are left behind.
--
-- It also updates the valid statues enum to reflect the ones in use.

begin;
  delete from job_run where status = 'completed';

  delete from job_run where job_name = 'job_run_cleaner';
  delete from job where name = 'job_run_cleaner';

  comment on index job_run_status_ix is
    'the job_run_status_ix indexes the commonly-used status field';

  comment on table job_run is
    'job_run is a table where each row represents an instance of a job run that is either actively running or has failed in some way.';

  -- Since we don't set completed anymore, but rather remove the job_run entry,
  -- remove 'completed' from the valid statuses.
  -- updates 7/03_job.up.sql.
  delete from job_run_status_enm where name = 'completed';

  alter table job_run_status_enm
    drop constraint only_predefined_job_status_allowed,
    add  constraint only_predefined_job_status_allowed
      check(name in ('running', 'failed', 'interrupted'));

commit;
