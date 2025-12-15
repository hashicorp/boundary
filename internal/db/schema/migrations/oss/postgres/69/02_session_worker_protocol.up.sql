-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table session_worker_protocol (
    session_id wt_public_id
      constraint session_fkey
        references session(public_id)
        on delete cascade
        on update cascade,
    worker_id wt_public_id
      constraint server_worker_fkey
        references server_worker(public_id)
        on delete cascade
        on update cascade
  );

  drop view session_list;
  -- Replaces view from 64/04_session_list.up.sql to add swp.worker_id
  -- Replaced in 72/03_session_list_perf_fix.up.sql
  create view session_list as
  select
    s.public_id,
    s.user_id,
    shsh.host_id,
    s.target_id,
    shsh.host_set_id,
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
    swp.worker_id,
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
      s.public_id = sc.session_id
    left join session_host_set_host shsh on
      s.public_id = shsh.session_id
    left join session_worker_protocol swp on
      s.public_id = swp.session_id;

commit;
