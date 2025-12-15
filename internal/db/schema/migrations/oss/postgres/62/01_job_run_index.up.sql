-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Delete any existing completed job_runs to make index
  -- creation faster and avoid one very expensive first cleaner job.
  delete from job_run where status='completed';

  -- Create index for faster deletes.
  create index job_run_status_ix on job_run (status);
  comment on index job_run_status_ix is
    'the job_run_status_ix is used by the job run cleaner job';

commit;
