-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- This series of expressions fixes the primary key on the server table
-- PG 12+
alter table session
  drop constraint if exists session_server_id_server_type_fkey;
-- PG 11
alter table session
  drop constraint if exists session_server_id_fkey;
alter table server
  drop constraint server_pkey;
alter table server
  drop column name;
alter table server
  add primary key (private_id);
alter table server
  add constraint server_id_must_not_be_empty
  check(length(trim(private_id)) > 0);
alter table session
  add constraint session_server_id_fkey
  foreign key (server_id)
  references server(private_id)
  on delete set null
  on update cascade;

create domain wt_bexprfilter as text
check(
  value is null
    or
    (
      length(trim(value)) > 0
        and
      length(trim(value)) <= 2048
    )
);
comment on domain wt_bexprfilter is
  'Text field with constraints for go-bexpr filters';

-- Add the worker filter to the target_tcp table and session table
alter table target_tcp
  add column worker_filter wt_bexprfilter;
alter table session
  add column worker_filter wt_bexprfilter;

-- Replace the immutable columns trigger from 50 to add worker_filter
-- Replaced in 59/01_target_ingress_egress_worker_filters.up.sql
drop trigger immutable_columns on session;
create trigger immutable_columns before update on session
    for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'connection_limit', 'create_time', 'endpoint', 'worker_filter');

-- Replaces the view created in 41 to include worker_filter
-- Replaced in 44/03_targets.up.sql
drop view target_all_subtypes;
create view target_all_subtypes
as
select
  public_id,
  scope_id,
  name,
  description,
  default_port,
  session_max_seconds,
  session_connection_limit,
  version,
  create_time,
  update_time,
  worker_filter,
  'tcp' as type
from target_tcp;

-- Replaces the view created in 50 to include worker_filter
drop view session_with_state;
create view session_with_state as
  select
    s.public_id,
    s.user_id,
    s.host_id,
    s.server_id,
    s.server_type,
    s.target_id,
    s.host_set_id,
    s.auth_token_id,
    s.scope_id,
    s.certificate,
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
    ss.state,
    ss.previous_end_time,
    ss.start_time,
    ss.end_time
  from
    session s,
    session_state ss
  where
    s.public_id = ss.session_id;

create domain wt_tagpair as text
check(
  value is not null
    and
  length(trim(value)) > 0
    and
  length(trim(value)) <= 512
    and
  lower(trim(value)) = value
);
comment on domain wt_tagpair is
  'Text field with constraints for key/value pairs';

create table server_tag (
  server_id text
    references server(private_id)
    on delete cascade
    on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  primary key(server_id, key, value)
);

commit;
