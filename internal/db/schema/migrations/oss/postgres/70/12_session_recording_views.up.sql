-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

create view session_recording_aggregate as
select
  rs.public_id,
  rs.storage_bucket_id,
  rs.session_id,
  rs.create_time,
  rs.update_time,
  rs.start_time,
  rs.end_time,
  rs.state,
  rs.error_details,
  sb.scope_id as storage_bucket_scope_id,
  -- fields that cover the user fields at creation time
  uh.public_id as user_history_public_id,
  uh.name as user_history_name,
  uh.description as user_history_description,
  uh.scope_id as user_history_scope_id,
  -- fields that cover the user's scope information at creation time
  ush.public_id as user_scope_history_public_id,
  ush.name as user_scope_history_name,
  ush.description as user_scope_history_description,
  ush.type as user_scope_history_type,
  ush.parent_id as user_scope_history_parent_id,
  ush.primary_auth_method_id as user_scope_history_primary_auth_method_id,
  -- fields that cover the target fields at creation time
  th.public_id as target_history_public_id,
  th.name as target_history_name,
  th.description as target_history_description,
  th.default_port as target_history_default_port,
  th.session_max_seconds as target_history_session_max_seconds,
  th.session_connection_limit as target_history_session_connection_limit,
  th.worker_filter as target_history_worker_filter,
  th.ingress_worker_filter as target_history_ingress_worker_filter,
  th.egress_worker_filter as target_history_egress_worker_filter,
  -- fields that cover the target's scope information at creation time
  tsh.public_id as target_scope_history_public_id,
  tsh.name as target_scope_history_name,
  tsh.description as target_scope_history_description,
  tsh.type as target_scope_history_type,
  tsh.parent_id as target_scope_history_parent_id,
  tsh.primary_auth_method_id as target_scope_history_primary_auth_method_id
from recording_session rs
 join storage_plugin_storage_bucket sb on
    rs.storage_bucket_id = sb.public_id
 join iam_user_hst uh on
    rs.user_hst_id = uh.history_id
 join iam_scope_hst as ush on
    rs.user_scope_hst_id = ush.history_id
 join target_ssh_hst th on
    rs.target_hst_id = th.history_id
 join iam_scope_hst as tsh on
    rs.target_project_hst_id = tsh.history_id;
comment on view session_recording_aggregate is
  'session_recording_aggregate contains the session recording resource with its storage bucket scope info and historical user info.';

commit;
