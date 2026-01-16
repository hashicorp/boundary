-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- This migration removes support for the job_jobs_to_run view as it is not used
-- anymore by the job repository.

begin;
  -- drops view from 7/03_job.up.sql
  drop view job_jobs_to_run;
commit;