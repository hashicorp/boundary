begin;

alter table job_run
    alter column server_id type text;
alter table job_run
    add constraint server_id_must_not_be_empty
        check(length(trim(server_id)) > 0);

commit;
