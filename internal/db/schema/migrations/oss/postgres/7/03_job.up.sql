-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

    create table job (
      plugin_id wt_plugin_id not null
        constraint plugin_fk
          references plugin(public_id)
          on delete cascade
          on update cascade,
      name wt_name not null,
      description wt_description not null,
      next_scheduled_run timestamp with time zone not null,
      primary key (plugin_id, name)
    );
    comment on table job is
      'job is a table where each row represents a unique job that can only have one running instance at any specific time.';

    create trigger immutable_columns before update on job
      for each row execute procedure immutable_columns('plugin_id', 'name');

    -- updated in 93/01_job_run_clean.up.sql
    create table job_run_status_enm (
      name text not null primary key
        constraint only_predefined_job_status_allowed
          check(name in ('running', 'completed', 'failed', 'interrupted'))
    );
    comment on table job_run_status_enm is
      'job_run_status_enm is an enumeration table where each row contains a valid job run state.';

    -- updated in 93/01_job_run_clean.up.sql
    insert into job_run_status_enm (name)
      values
      ('running'),
      ('completed'),
      ('failed'),
      ('interrupted');

    create table job_run (
      private_id wh_dim_id primary key default wh_dim_id(),
      job_plugin_id wt_plugin_id not null,
      job_name wt_name not null,
      server_id wt_private_id
        constraint server_fkey
          references server(private_id)
          on delete set null
          on update cascade,
      create_time wt_timestamp,
      update_time wt_timestamp,
      end_time timestamp with time zone,
      completed_count int not null default 0
        constraint completed_count_can_not_be_negative
          check(completed_count >= 0),
      total_count int not null default 0
        constraint total_count_can_not_be_negative
          check(total_count >= 0),
      status text not null default 'running'
        constraint job_run_status_enm_fkey
          references job_run_status_enm (name)
          on delete restrict
          on update cascade,

      constraint job_run_completed_count_less_than_equal_to_total_count
        check(completed_count <= total_count),

      constraint job_fkey
      foreign key (job_plugin_id, job_name)
        references job (plugin_id, name)
        on delete cascade
        on update cascade
    );
    comment on table job_run is
      'job_run is a table where each row represents an instance of a job run that is either actively running or has already completed.';

    create unique index job_run_status_constraint
      on job_run (job_plugin_id, job_name)
      where status = 'running';

    create trigger update_time_column before update on job_run
      for each row execute procedure update_time_column();

    create trigger default_create_time_column before insert on job_run
      for each row execute procedure default_create_time();

    create trigger immutable_columns before update on job_run
      for each row execute procedure immutable_columns('private_id', 'job_plugin_id', 'job_name', 'create_time');

    -- dropped in 93/02_drop_job_jobs_to_run.up.sql
    create view job_jobs_to_run as
      with
      running_jobs (job_plugin_id, job_name) as (
        select job_plugin_id, job_name
          from job_run
          where status = 'running'
      ),
      final (job_plugin_id, job_name, next_scheduled_run) as (
        select plugin_id, name, next_scheduled_run
          from job j
          where next_scheduled_run <= current_timestamp
          and not exists (
            select
              from running_jobs
              where job_plugin_id = j.plugin_id
              and job_name = j.name
          )
      )
      select job_plugin_id, job_name, next_scheduled_run from final;

commit;
