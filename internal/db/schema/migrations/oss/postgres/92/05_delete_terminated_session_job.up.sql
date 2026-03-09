-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table session_delete_terminated_job (
    batch_size int not null
      constraint batch_size_must_be_greater_than_0
        check(batch_size > 0),
    create_time wt_timestamp,
    update_time wt_timestamp
  );
  comment on table session_delete_terminated_job is
    'session_delete_terminated_job is a single row table that contains settings for the delete terminated sessions job.';

  -- this index ensures that there will only ever be one row in the
  -- table. see:
  -- https://www.postgresql.org/docs/current/indexes-expressional.html
  create unique index session_delete_terminated_job_one_row
    on session_delete_terminated_job((batch_size is not null));

  create trigger immutable_columns before update on session_delete_terminated_job
    for each row execute procedure immutable_columns('create_time');

  create trigger default_create_time_column before insert on session_delete_terminated_job
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on session_delete_terminated_job
    for each row execute procedure update_time_column();

  insert into session_delete_terminated_job(batch_size) values(5000);

commit;

