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
  worker_reported_name wt_name unique
    -- TODO: When we are recording the worker node's key id allow that as an
    --  alternative value that must be set besides worker_reported_name if
    --  last_status_time is set.
    constraint worker_reported_name_must_be_set_by_status
      check (
          (last_status_time is null and worker_reported_name is null)
          or
          (last_status_time is not null and worker_reported_name is not null)
        ),
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

create trigger update_version_column after update of version, description, name, address on server_worker
  for each row execute procedure update_version_column();

create function update_server_worker_last_status_time()
  returns trigger
as $$
begin
  new.last_status_time = now();
  return new;
end;
$$ language plpgsql;
comment on function update_server_worker_last_status_time is
  'function used to update the last_status_time column in server_worker to now';

create trigger update_server_worker_last_status_time_column before update of worker_reported_address, worker_reported_name on server_worker
  for each row execute procedure update_server_worker_last_status_time();

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

-- worker_aggregate view allows the worker and configuration to be read at the
-- same time.
create view server_worker_aggregate as
  with worker_config_tags(worker_id, source, tags) as (
    select
      ct.worker_id,
      ct.source,
      -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
      string_agg(distinct concat_ws('Y', ct.key, ct.value), 'Z') as tags
    from server_worker_tag ct
    group by ct.worker_id, ct.source
  )
select
  w.public_id,
  w.scope_id,
  w.description,
  w.name,
  w.address,
  w.create_time,
  w.update_time,
  w.version,
  w.worker_reported_name,
  w.worker_reported_address,
  w.last_status_time,
  -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
  wt.tags as api_tags,
  ct.tags as worker_config_tags
from server_worker w
  left join worker_config_tags wt on
      w.public_id = wt.worker_id and wt.source = 'api'
  left join worker_config_tags ct on
    w.public_id = ct.worker_id and ct.source = 'configuration';
comment on view server_worker_aggregate is
'server_worker_aggregate contains the worker resource with its worker provided config values and its configuration and api provided tags.';


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