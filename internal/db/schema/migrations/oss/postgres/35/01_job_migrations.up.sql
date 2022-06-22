begin;

-- The job_run table has a foreign key to the server_controller private_id.
-- While this column is called a prviate_id it does not implement the wt_private_id
-- domain type, and therefore does not have a minimum length of 10 characters.

-- Drop constraint that requires controller_id to be at least 10 chars
alter table job_run
  drop constraint controller_id_must_be_at_least_10_characters;

-- Add a not empty contraint to the controller_id
alter table job_run
  add constraint controller_id_must_not_be_empty
    check(
      length(trim(controller_id)) > 0
    );

commit;
