begin;

-- Split the server table into two new tables: controller and worker
-- Worker table takes the place of the server table.
-- instead of the private_id we use a wt_public_id field named public_id since
-- workers will now be exposed as resources in boundary.
create table server_worker (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null
    references iam_scope_global(scope_id)
      on delete cascade
      on update cascade,
  description wt_description,
  name wt_name unique,
  -- The address can be null since it is an optional value from the API.
  address wt_network_address,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  constraint server_worker_scope_id_name_uq
    unique(scope_id, name)
);
comment on table server_worker  is
  'server_worker is a table where each row represents a Boundary worker.';

create trigger immutable_columns before update on server_worker
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on server_worker
  for each row execute procedure default_create_time();

create trigger worker_insert_time_column before insert on server_worker
  for each row execute procedure update_time_column();

create trigger worker_update_time_column before update on server_worker
  for each row execute procedure update_time_column();

-- Create table worker tag
create table server_worker_tag (
  worker_id wt_public_id
    constraint server_worker_fkey
      references server_worker(public_id)
        on delete cascade
        on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  primary key(worker_id, key, value)
);

-- Aaand drop server_tag
drop table server_tag;

create table server_controller (
  private_id text primary key,
  description wt_description,
  address wt_network_address not null,
  create_time wt_timestamp,
  update_time wt_timestamp
);
comment on table server_controller  is
  'server_controller is a table where each row represents a Boundary controller.';

create trigger immutable_columns before update on server_controller
  for each row execute procedure immutable_columns('private_id','create_time');

create trigger default_create_time_column before insert on server_controller
  for each row execute procedure default_create_time();

create trigger controller_insert_time_column before insert on server_controller
  for each row execute procedure update_time_column();

create trigger controller_update_time_column before update on server_controller
  for each row execute procedure update_time_column();

-- Update session table to use worker_id instead of server_id, drop view first because of dependency on server type
drop view session_list;

-- Update session table to use worker_id instead of server_id
-- Updating the session table modified in 01/01_server_tags_migrations.up.sql
drop trigger update_version_column
  on session;
alter table session
  drop constraint session_server_id_fkey,
  drop column server_type,
  drop column server_id;
create trigger
  update_version_column
  after update of version, termination_reason, key_id, tofu_token on session
  for each row execute procedure update_version_column();

-- Update session_connection table to use worker_id instead of server_id
-- Table last updated in 21/02_session.up.sql
alter table session_connection
  drop column server_id,
  add column worker_id wt_public_id,
  add constraint server_worker_fkey
    foreign key (worker_id)
      references server_worker (public_id)
      on delete set null
      on update cascade;

-- We only need to migrate the private ids to maintain the job_run foreign key
-- constraint.  Since we are changing the constraints on the address and
-- description, we wont migrate that data and rely on the controllers to update
-- those correctly when they start up.
insert
  into server_controller (private_id, address)
select s.private_id, 'migrated address placeholder'
  from  server s
  where type='controller';

-- Update job run table so that server id references controller id
alter table job_run
  rename column server_id to controller_id;
alter table job_run
  drop constraint server_fkey,
  add constraint server_controller_fkey
    foreign key (controller_id)
      references server_controller (private_id)
      on delete set null
      on update cascade;

-- Replaces the view created in 9/01.
-- Remove the worker id from this view.  In actuality this is almost a no-op
-- because no server information was ever getting populated here due to a bug
-- in the update mask when updating a session at the time we activate a session.
create view session_list as
  select
    s.public_id, s.user_id, s.host_id, s.target_id,
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