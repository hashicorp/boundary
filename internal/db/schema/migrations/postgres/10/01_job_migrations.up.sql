begin;

alter table job_run
    alter column server_id type text;

commit;
