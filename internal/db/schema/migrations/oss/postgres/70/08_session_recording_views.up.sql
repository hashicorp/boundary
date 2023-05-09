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
  ush.primary_auth_method_id as user_scope_history_primary_auth_method_id
from recording_session rs
 join storage_plugin_storage_bucket sb on
    rs.storage_bucket_id = sb.public_id
 join iam_user_hst uh on
    rs.user_hst_id = uh.history_id
 join iam_scope_hst as ush on
    rs.user_scope_hst_id = ush.history_id;
comment on view session_recording_aggregate is
  'session_recording_aggregate contains the session recording resource with its storage bucket scope info and historical user info.';

commit;
