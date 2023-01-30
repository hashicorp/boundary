begin;

-- Update tables to add ingress_worker_filter and egress_worker_filter
alter table session
  add column egress_worker_filter wt_bexprfilter,
  add column ingress_worker_filter wt_bexprfilter;

alter table target_tcp
  add column egress_worker_filter wt_bexprfilter,
  add column ingress_worker_filter wt_bexprfilter;

-- Trigger functions to ensure that worker_filter and ingress/egress_worker_filter are mutually exclusive
-- and that worker_filter can only be updated
create function validate_filter_values_on_insert() returns trigger
as $$
begin
  if new.worker_filter is not null then
    raise exception 'worker_filter is deprecated and cannot be set';
  end if;

  return new;

end;
$$ language plpgsql;

create function validate_filter_values_on_update() returns trigger
as $$
begin
  if new.egress_worker_filter is not null then
    if new.worker_filter = old.worker_filter then
      new.worker_filter = null;
    end if;
  end if;

  if new.ingress_worker_filter is not null then
    if new.worker_filter = old.worker_filter then
      new.worker_filter = null;
    end if;
  end if;

  if new.worker_filter is not null then
-- New worker_filter values are only allowed as an update to support users with existing worker_filter values
    if old.worker_filter is null then
      raise exception 'worker_filter is deprecated and cannot be set';
    end if;

    if new.egress_worker_filter is not null then
      raise exception 'cannot set worker_filter and egress_filter; they are mutually exclusive fields';
    end if;

    if new.ingress_worker_filter is not null then
      raise exception 'cannot set worker_filter and ingress_filter; they are mutually exclusive fields';
    end if;
  end if;

  return new;

end;
$$ language plpgsql;

create trigger update_tcp_target_filter_validate before update on target_tcp
  for each row execute procedure validate_filter_values_on_update();

create trigger insert_tcp_target_filter_validate before insert on target_tcp
  for each row execute procedure validate_filter_values_on_insert();

-- Update views

-- Replaces target_all_subtypes defined in 44/03_targets.up.sql
-- Using create or replace instead of delete/create, as views whx_credential_dimension_source and
-- whx_host_dimension_source depend on this view and are unaffected by the worker_filter changes
create or replace view target_all_subtypes as
select public_id,
   project_id,
   name,
   description,
   default_port,
   session_max_seconds,
   session_connection_limit,
   version,
   create_time,
   update_time,
   worker_filter,
   egress_worker_filter,
   ingress_worker_filter,
   'tcp' as type
from target_tcp;

-- Replaces view from 56/06_add_session_private_key_column.up.sql
-- Replaced in 60/02_sessions.up.sql
drop view session_list;
create view session_list as
select
  s.public_id,
  s.user_id,
  s.host_id,
  s.target_id,
  s.host_set_id,
  s.auth_token_id,
  s.project_id,
  s.certificate,
  s.certificate_private_key,
  s.expiration_time,
  s.connection_limit,
  s.tofu_token,
  s.key_id,
  s.termination_reason,
  s.version,
  s.create_time,
  s.update_time,
  s.endpoint,
  s.worker_filter,
  s.egress_worker_filter,
  s.ingress_worker_filter,
  ss.state,
  ss.previous_end_time,
  ss.start_time,
  ss.end_time,
  sc.public_id as connection_id,
  sc.client_tcp_address,
  sc.client_tcp_port,
  sc.endpoint_tcp_address,
  sc.endpoint_tcp_port,
  sc.bytes_up,
  sc.bytes_down,
  sc.closed_reason
from session s
  join session_state ss on
    s.public_id = ss.session_id
  left join session_connection sc on
    s.public_id = sc.session_id;

-- Update session immutable columns
drop trigger immutable_columns on session;
create trigger immutable_columns before update on session
  for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'connection_limit',
    'create_time', 'endpoint', 'worker_filter', 'egress_worker_filter', 'ingress_worker_filter');

commit;
