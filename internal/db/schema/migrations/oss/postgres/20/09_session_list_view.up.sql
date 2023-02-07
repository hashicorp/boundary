-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

-- Replaces the view created in 1/01 to include connections
-- Replaced in 31/0_session_list_no_connections
drop view session_with_state;
create view session_list as
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
    ss.end_time,
    sc.public_id as connection_id,
    sc.client_tcp_address,
    sc.client_tcp_port,
    sc.endpoint_tcp_address,
    sc.endpoint_tcp_port,
    sc.bytes_up,
    sc.bytes_down,
    sc.closed_reason
  from
    session s
  join
    session_state ss
  on
    s.public_id = ss.session_id
  left join
    session_connection sc
  on
    s.public_id = sc.session_id;

commit;
