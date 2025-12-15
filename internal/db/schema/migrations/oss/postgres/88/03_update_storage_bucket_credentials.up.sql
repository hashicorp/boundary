-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create view update_worker_storage_bucket_credential as
    select distinct
      sb.public_id,
      sb.scope_id,
      sb.name,
      sb.description,
      sb.bucket_name,
      sb.bucket_prefix,
      sb.worker_filter,
      sb.attributes,
      sb.version,
      sb.plugin_id,
      sb.storage_bucket_credential_id,
      pl.name as plugin_name,
      pl.description as plugin_description,
      sbcms.secrets_encrypted as ct_secrets,
      sbcms.key_id as key_id

    from storage_plugin_storage_bucket sb
    join plugin pl
      on sb.plugin_id = pl.public_id
    left join storage_bucket_credential_managed_secret sbcms
      on  sb.storage_bucket_credential_id = sbcms.private_id;
  comment on view update_worker_storage_bucket_credential is
    'update_worker_storage_bucket_credential is used find workers using storage bucket credentials that need to be updated to the latest version.';

commit;