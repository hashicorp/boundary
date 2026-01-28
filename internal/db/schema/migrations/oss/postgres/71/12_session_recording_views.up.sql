-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create view recording_channel_ssh_aggregate as
select
  rch.public_id,
  rch.recording_connection_id,
  rch.create_time,
  rch.update_time,
  rch.start_time,
  rch.end_time,
  rch.bytes_up,
  rch.bytes_down,
  rch.channel_type,
  rchsc.program as channel_program
from recording_channel_ssh rch
  left join recording_channel_ssh_session_channel rchsc on
    rch.public_id = rchsc.recording_channel_id;
comment on view recording_channel_ssh_aggregate is
  'recording_channel_ssh_aggregate contains the ssh channel recording info along with other info needed for displaying it on the api.';


-- replaced in 82/02_recording_session.up.sql
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
  rs.endpoint,
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
  th.default_client_port as target_history_default_client_port,
  th.enable_session_recording as target_history_enable_session_recording,
  th.storage_bucket_id as target_history_storage_bucket_id,
  -- fields that cover the target's scope information at creation time
  tsh.public_id as target_scope_history_public_id,
  tsh.name as target_scope_history_name,
  tsh.description as target_scope_history_description,
  tsh.type as target_scope_history_type,
  tsh.parent_id as target_scope_history_parent_id,
  tsh.primary_auth_method_id as target_scope_history_primary_auth_method_id,
  -- static
  -- host catalogs
  shch.public_id as static_catalog_history_public_id,
  shch.project_id as static_catalog_history_project_id,
  shch.name as static_catalog_history_name,
  shch.description as static_catalog_history_description,
  -- hosts
  shh.public_id as static_host_history_public_id,
  shh.name as static_host_history_name,
  shh.description as static_host_history_description,
  -- catalog_id is unnecessary as its inferred from the host catalog row
  shh.address as static_host_history_address,

  -- plugin
  -- host catalogs
  hpch.public_id as plugin_catalog_history_public_id,
  hpch.project_id as plugin_catalog_history_project_id,
  hpch.name as plugin_catalog_history_name,
  hpch.description as plugin_catalog_history_description,
  hpch.attributes as plugin_catalog_history_attributes,
  hpch.plugin_id as plugin_catalog_history_plugin_id,
  -- hosts
  hph.public_id as plugin_host_history_public_id,
  hph.name as plugin_host_history_name,
  hph.description as plugin_host_history_description,
  -- catalog_id is unnecessary as its inferred from the host catalog row
  hph.external_id as plugin_host_history_external_id,
  hph.external_name as plugin_host_history_external_name

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
    rs.target_project_hst_id = tsh.history_id
 left join static_host_catalog_hst as shch on
    rs.host_catalog_hst_id = shch.history_id
 left join host_plugin_catalog_hst as hpch on
    rs.host_catalog_hst_id = hpch.history_id
 left join static_host_hst as shh on
    rs.host_hst_id = shh.history_id
 left join host_plugin_host_hst as hph on
    rs.host_hst_id = hph.history_id;
comment on view session_recording_aggregate is
  'session_recording_aggregate contains the session recording resource with its storage bucket scope info and historical user info.';

commit;
