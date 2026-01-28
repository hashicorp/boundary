-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Replaced in 88/01_storage_bucket_credential.up.sql
  create view find_session_recordings_for_delete as
    select
      -- fields for session recordings
      rs.public_id,
      rs.storage_bucket_id,

      -- fields for storage buckets. note this is ALL storage bucket fields
      sb.scope_id    as storage_bucket_scope_id,
      sb.name        as storage_bucket_name,
      sb.description as storage_bucket_description,
      sb.create_time as storage_bucket_create_time,
      sb.update_time as storage_bucket_update_time,
      sb.version     as storage_bucket_version,
      sb.plugin_id,
      sb.bucket_name,
      sb.bucket_prefix,
      sb.worker_filter,
      sb.attributes,
      sb.secrets_hmac,

      -- fields for storage bucket secrets
      sbs.secrets_encrypted,
      sbs.key_id,

      -- fields for storage bucket plugins
      plg.scope_id    as plugin_scope_id,
      plg.name        as plugin_name,
      plg.description as plugin_description

    from recording_session rs
      left join storage_plugin_storage_bucket sb
        on sb.public_id = rs.storage_bucket_id
      left join storage_plugin_storage_bucket_secret sbs
        on sbs.storage_bucket_id = sb.public_id
      left join plugin plg
        on plg.public_id = sb.plugin_id
    where rs.delete_after < now() or rs.delete_time < now()
    order by rs.delete_time desc, rs.delete_after desc;
  comment on view find_session_recordings_for_delete is
    'find_session_recordings_for_delete is used by the delete_session_recording job to find all '
    'session recordings that need to be automatically deleted along with their storage buckets.';

commit;
