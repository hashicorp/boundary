-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- The job_run table has a foreign key to the server_controller private_id.
-- While this column is called a prviate_id it does not implement the wt_private_id
-- domain type, and therefore does not have a minimum length of 10 characters.

create domain wt_controller_id as text
  check(
    length(trim(value)) > 0
  );
comment on domain wt_controller_id is
  'A text column that can only be null or not empty representing the id of the controller.';

-- Drop constraint that requires controller_id to be at least 10 chars
-- Alters controller_id column defined in 34/02_worker_controller_tables.up.sql
alter table job_run
  drop constraint controller_id_must_be_at_least_10_characters,
  alter column controller_id type wt_controller_id;

-- Add a not empty contraint to the private_id
-- Updates column private_id defined in 34/02_worker_controller_tables.up.sql
alter table server_controller
    alter column private_id type wt_controller_id;

commit;
