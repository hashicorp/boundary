begin;

-- Split the server table into two new tables: controller and worker
create table server_controller (
  private_id text primary key,
  description wt_description,
  address text not null,
  create_time wt_timestamp,
  update_time wt_timestamp
);

create trigger immutable_columns before update on server_controller
  for each row execute procedure immutable_columns('private_id','create_time');

create trigger default_create_time_column before insert on server_controller
  for each row execute procedure default_create_time();

create trigger controller_insert_time_column before insert on server_controller
  for each row execute procedure update_time_column();

create trigger controller_update_time_column before update on server_controller
  for each row execute procedure update_time_column();

-- Worker table adds the field: name
create table server_worker (
  private_id text primary key,
  description wt_description,
  name wt_name unique,
  address text not null,
  create_time wt_timestamp,
  update_time wt_timestamp
);

create trigger immutable_columns before update on server_worker
  for each row execute procedure immutable_columns('private_id','create_time');

create trigger default_create_time_column before insert on server_worker
  for each row execute procedure default_create_time();

create trigger worker_insert_time_column before insert on server_worker
  for each row execute procedure update_time_column();

create trigger worker_update_time_column before update on server_worker
  for each row execute procedure update_time_column();

-- TODO: Migrate server entries to worker and controller tables, if necessary

-- Create table worker tag
create table server_worker_tag (
  worker_id text
    references server_worker(private_id)
      on delete cascade
      on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  primary key(worker_id, key, value)
);

-- Aaand drop server_tag
drop table server_tag;

-- Update session table to use worker_id instead of server_id
alter table session
  drop constraint session_server_id_fkey;
drop trigger update_version_column
  on session;
alter table session
  drop column server_type cascade;

alter table session
  rename column server_id to worker_id;
alter table session
  add constraint session_worker_id_fkey
    foreign key (worker_id)
      references server_worker(private_id)
      on delete set null
      on update cascade;

create trigger
  update_version_column
  after update of version, termination_reason, key_id, tofu_token, worker_id on session
  for each row execute procedure update_version_column();

-- Update session_connection table to use worker_id instead of server_id
alter table session_connection
  drop constraint server_fkey;

alter table session_connection
  rename column server_id to worker_id;
alter table session_connection
  add constraint worker_fkey
    foreign key (worker_id)
      references server_worker (private_id)
      on delete set null
      on update cascade;

-- Update job run table so that server id references controller id
alter table job_run
  drop constraint server_fkey;
alter table job_run
  add constraint server_fkey
    foreign key (server_id)
      references server_controller (private_id)
      on delete set null
      on update cascade;

-- Replaces the view created in 9/01 to include worker id instead of server id and server type
drop view if exists session_list;

create view session_list as

  select
    s.public_id, s.user_id, s.host_id, s.worker_id, s.target_id,
    s.host_set_id, s.auth_token_id, s.scope_id, s.certificate,s.expiration_time,
    s.connection_limit, s.tofu_token, s.key_id, s.termination_reason, s.version,
    s.create_time, s.update_time, s.endpoint, s.worker_filter,
    ss.state, ss.previous_end_time, ss.start_time, ss.end_time, sc.public_id as connection_id,
    sc.client_tcp_address, sc.client_tcp_port, sc.endpoint_tcp_address, sc.endpoint_tcp_port,
    sc.bytes_up, sc.bytes_down, sc.closed_reason
  from session s
  join session_state ss on
    s.public_id = ss.session_id
  left join session_connection sc on
    s.public_id = sc.session_id;

-- Drop the server and server_type_enm tables
drop table server;
drop table server_type_enm;

commit;