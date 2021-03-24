begin;

create table job (
    private_id wt_private_id primary key,
    name wt_name not null,
    description wt_description not null,
    code text not null,
    next_scheduled_run timestamp not null default current_timestamp,

    constraint job_name_code_uq
        unique(name, code)
);

comment on table job is
    'job is a table where each row represents a unique job that can only have one running instance at any specific time.';

create trigger immutable_columns before update on job
    for each row execute procedure immutable_columns('private_id', 'name', 'code');

create table job_run_status_enm (
    name text not null primary key
        constraint only_predefined_job_status_allowed
            check(name in ('running', 'complete', 'failed', 'interrupted'))
);

comment on table job_run_status_enm is
    'job_run_status_enm is an enumeration table where each row contains a valid job run state.';

insert into job_run_status_enm (name)
    values
    ('running'),
    ('complete'),
    ('failed'),
    ('interrupted');


create table job_run (
     id serial primary key,
     job_id text not null
         constraint job_fkey
             references job(private_id)
             on delete cascade
             on update cascade,
     server_id text
         constraint server_fkey
             references server(private_id)
             on delete set null
             on update cascade,
     create_time wt_timestamp,
     update_time wt_timestamp,
     end_time timestamp with time zone,
     completed_count int not null
        default 0
        constraint completed_count_can_not_be_negative
            check(completed_count >= 0),
     total_count int not null
         default 0
         constraint total_count_can_not_be_negative
            check(total_count >= 0),
     status text not null
         constraint status_enm_fkey
             references job_run_status_enm (name)
             on delete restrict
             on update cascade,

     constraint job_run_completed_count_less_than_equal_to_total_count
         check(completed_count <= total_count)
);

comment on table job_run is
    'job_run is a table where each row represents an instance of a job run that is either actively running or has already completed.';

create unique index job_run_status_constraint
    on job_run (job_id)
    where status = 'running';

create trigger update_time_column before update on job_run
    for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on job_run
    for each row execute procedure default_create_time();

create trigger immutable_columns before update on job_run
    for each row execute procedure immutable_columns('id', 'job_id', 'server_id', 'create_time');
