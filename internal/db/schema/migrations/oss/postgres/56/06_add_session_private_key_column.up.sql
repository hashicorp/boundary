-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- nullable because it will not be set for sessions that are active
  -- during the upgrade to this version.
  alter table session add column certificate_private_key bytea null;

  -- Replaces the view created in 44/05_session_list_no_connections
  -- Replaced in 59/01_target_ingress_egress_worker_filters.up.sql
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

commit;
