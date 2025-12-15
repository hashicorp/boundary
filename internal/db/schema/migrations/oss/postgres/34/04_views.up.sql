-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- worker_aggregate view allows the worker and configuration to be read at the
-- same time.
-- Updated in 51/01_server_worker_release_version.up.sql
create view server_worker_aggregate as
with worker_config_tags(worker_id, source, tags) as (
  select
    ct.worker_id,
    ct.source,
    -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
    string_agg(distinct concat_ws('Y', ct.key, ct.value), 'Z') as tags
  from server_worker_tag ct
  group by ct.worker_id, ct.source
),
 connection_count (worker_id, count) as (
   select
     worker_id,
     count(1) as count
   from session_connection
   where closed_reason is null
   group by worker_id
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
  w.last_status_time,
  w.type,
  cc.count as active_connection_count,
  -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
  wt.tags as api_tags,
  ct.tags as worker_config_tags
from server_worker w
  left join worker_config_tags wt on
      w.public_id = wt.worker_id and wt.source = 'api'
  left join worker_config_tags ct on
      w.public_id = ct.worker_id and ct.source = 'configuration'
  left join connection_count as cc on
      w.public_id = cc.worker_id;
comment on view server_worker_aggregate is
  'server_worker_aggregate contains the worker resource with its worker provided config values and its configuration and api provided tags.';

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

commit;