-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Replaces the view created in 69/02_session_worker_protocol.up.sql
  -- Replaced in 92/02_session_state_tstzrange.up.sql
  drop view session_list;
  create view session_list as
      select s.public_id,
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
             ss.end_time
        from session s
        join session_state            ss on s.public_id = ss.session_id
   left join session_host_set_host  shsh on s.public_id = shsh.session_id
   left join session_worker_protocol swp on s.public_id = swp.session_id;

commit;
