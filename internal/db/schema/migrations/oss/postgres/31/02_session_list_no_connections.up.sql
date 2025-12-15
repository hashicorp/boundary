-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Replaces the view created in 2/09_session_list_view
drop view session_list;
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
    ss.end_time
  from
    session s
  join
    session_state ss
  on
    s.public_id = ss.session_id;

commit;
