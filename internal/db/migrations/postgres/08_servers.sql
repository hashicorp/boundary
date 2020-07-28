begin;

create table job_type_enm (
  string text not null primary key check (
    string in ('unknown', 'connection')
  )
);

insert into job_type_enm (string)
values
  ('unknown'),
  ('connection');

create table job_status_enm (
  string text not null primary key check (
    string in ('unknown', 'pending', 'active', 'canceling', 'canceled', 'complete')
  )
);

-- TODO: Add a trigger to verify that status cannot go backwards, e.g. can't go
-- from any existing state to 'pending'

insert into job_status_enm (string)
values
  ('unknown'),
  ('pending'),
  ('active'),
  ('canceling'),
  ('canceled'),
  ('complete');

create table jobs_worker (
    id text primary key,
    name text unique,
    description text,
    first_seen_time wt_timestamp,
    last_seen_time wt_timestamp
  );

create table jobs_controller (
    id text primary key,
    name text unique,
    description text,
    first_seen_time wt_timestamp,
    last_seen_time wt_timestamp
  );

create table jobs_job (
    public_id wt_public_id primary key,
    pending_time wt_timestamp,
    active_time wt_timestamp,
    worker_name text not null,
    worker_description text,
    canceling_time wt_timestamp,
    canceled_time wt_timestamp,
    complete_time wt_timestamp,
    type job_type_enm not null,
    status job_status_enm not null,
    worker_name text not null,
    worker_description text,
    scope_id wt_scope_id not null,
    scope_name text,
    scope_description text,
    requesting_user_id wt_user_id not null,
    requesting_user_name text,
    requesting_user_description text,
    canceling_user_id wt_user_id not null,
    canceling_user_name text,
    canceling_user_description text
  );

-- TODO: Create a trigger that enforces forward progress during updates to
-- status and updates timestamps based on how the status changes
