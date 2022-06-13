begin;

-- Split the server table into two new tables: controller and worker

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
  last_status_time timestamp with time zone,
  constraint last_status_time_not_before_create_time
    check (last_status_time >= create_time),
  -- This is the calculated address that the worker reports it is reachable on.
  -- This must be set if the worker has ever received a status update.
  worker_reported_address wt_network_address
    constraint worker_reported_address_must_be_set_by_status
      check (
          (last_status_time is null and worker_reported_address is null)
          or
          (last_status_time is not null and worker_reported_address is not null)
        ),
  -- This is the name that the worker reports in it's status updates.
  worker_reported_name wt_name
    constraint worker_reported_name_must_be_set_by_status
      check (
          (last_status_time is null and worker_reported_name is null)
          or
          (last_status_time is not null and worker_reported_name is not null)
          or
          (last_status_time is not null and key_id is not null)
        )
    constraint worker_reported_name_must_be_lowercase
      check (lower(trim(worker_reported_name)) = worker_reported_name)
    constraint worker_reported_name_only_has_printable_characters
      check (worker_reported_name !~ '[^[:print:]]'),
  key_id text
    constraint worker_reported_key_id_must_be_set_by_status
    check (
      (last_status_time is null and key_id is null)
      or
      (last_status_time is not null and worker_reported_name is not null)
      or
      (last_status_time is not null and key_id is not null)
    ),
  constraint server_worker_scope_id_name_uq
    unique(scope_id, name),
  constraint server_worker_scope_id_worker_reported_name_uq
    unique(scope_id, worker_reported_name)
);
comment on table server_worker  is
  'server_worker is a table where each row represents a Boundary worker.';

create or replace function
  validate_key_id_on_insert()
  returns trigger
as $$
begin
    if new.key_id is not null then
      perform from
        worker_auth_authorized
      where
        worker_key_identifier= new.key_id;
    if not found then
      raise 'key_id %s does not match a worker auth record', new.key_id;
    end if;
  end if;
  return new;
end;
$$ language plpgsql;

create trigger validate_key_id_on_insert before insert on server_worker
  for each row execute procedure validate_key_id_on_insert();

create trigger immutable_columns before update on server_worker
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on server_worker
  for each row execute procedure default_create_time();

create trigger worker_insert_time_column before insert on server_worker
  for each row execute procedure update_time_column();

create trigger worker_update_time_column before update on server_worker
  for each row execute procedure update_time_column();

create trigger update_version_column after update of version, description, name, address on server_worker
  for each row execute procedure update_version_column();

create function update_server_worker_update_last_status_time_column()
  returns trigger
as $$
begin
  new.last_status_time = now();
  return new;
end;
$$ language plpgsql;
comment on function update_server_worker_update_last_status_time_column is
  'function used to update the last_status_time column in server_worker to now';

create trigger update_server_worker_last_status_time_column before update of worker_reported_address, worker_reported_name on server_worker
  for each row execute procedure update_server_worker_update_last_status_time_column();

create function insert_server_worker_update_last_status_time_column()
  returns trigger
as $$
begin
  if new.worker_reported_address is not null or new.worker_reported_name is not null then
    new.last_status_time = now();
  end if;
  return new;
end;
$$ language plpgsql;
comment on function insert_server_worker_update_last_status_time_column is
  'function used to update the last_status_time column in server_worker to now';

create trigger insert_server_worker_last_update_time_column before insert on server_worker
  for each row execute procedure insert_server_worker_update_last_status_time_column();

-- Create table worker tag
create table server_worker_tag_enm (
  source text primary key
    constraint only_predefined_server_worker_tag_sources_allowed
      check (
          source in ('configuration', 'api')
        )
);

insert into server_worker_tag_enm (source)
values
  ('configuration'),
  ('api');

create table server_worker_tag (
  worker_id wt_public_id
    constraint server_worker_fkey
      references server_worker(public_id)
        on delete cascade
        on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  source text not null
    constraint server_worker_tag_enm_fkey
      references server_worker_tag_enm(source)
        on delete restrict
        on update cascade,
  primary key(worker_id, key, value, source)
);


-- Aaand drop server_tag
drop table server_tag;

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

-- Update job run table so that server id references controller id
-- We are not migrating the values from server_id to controller_id. The fkey
-- constraint says that server_id can be set to null when the server is deleted
-- which is what this migration does (removing all records from the server table).
-- Not migrating values make it easier to change types in the server_worker and
-- server_controller tables (like from text to wt_public_id or text to wt_address)
-- without having to worry about old values being valid in the new types.
-- Finally, neither jobs nor servers are exposed out of boundary so the risk of
-- losing data that would be useful later on is diminished.
alter table job_run
  add column controller_id wt_private_id,
  drop column server_id;
alter table job_run
  add constraint server_controller_fkey
    foreign key (controller_id)
      references server_controller (private_id)
      on delete set null
      on update cascade;

-- Since the above alter tables sets all controller_ids to null running jobs
-- can no longer be reclaimed by any controller and should be considered
-- interrupted.
update job_run
set
  status = 'interrupted',
  end_time = current_timestamp
where
    status = 'running';

-- Drop the server and server_type_enm tables
drop table server;
drop table server_type_enm;

commit;