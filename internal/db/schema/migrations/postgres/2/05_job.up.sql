begin;

create table job (
    id text primary key,
    name wt_name not null,
    description wt_description not null
);
comment on table job is
    'job is a base table where each row represents a unique job that can only have one running instance at any specific time.';

create table job_run (
     id serial primary key,
     job_id text not null
         constraint job_fk
             references job(id)
             on delete cascade
             on update cascade,
     server_id wt_private_id not null
         constraint server_fk
             references server(private_id)
             on delete cascade
             on update cascade,
     scheduled_start_time timestamp not null,
     start_time timestamp,
     end_time timestamp,
     last_heartbeat timestamp,
     completed_count int,
     total_count int,

     constraint job_run_job_id_end_time_uq
         unique(job_id, end_time)
);

comment on table job_run is
    'job_run is a table where each row represents an instance of a job run that is either actively running or has already completed.';

create table job_run_interrupt (
    old_run_id integer not null
       constraint old_job_run_fk
           references job_run(id)
           on delete cascade
           on update cascade,
    new_run_id integer not null
       constraint new_job_run_fk
           references job_run(id)
           on delete cascade
           on update cascade
);

comment on table job_run_interrupt is
    'job_run_interrupt is a table where each row represents a request to kill a running job and the job run that was created to replace it.';

commit;