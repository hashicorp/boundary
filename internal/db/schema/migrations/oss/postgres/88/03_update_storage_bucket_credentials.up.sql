-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create view update_worker_storage_bucket_credential as
    select distinct
      sb.scope_id as storage_bucket_scope_id,
      sb.name as storage_bucket_name,
      sb.description as storage_bucket_description,
      sb.bucket_name as storage_bucket_bucket_name,
      sb.bucket_prefix as storage_bucket_bucket_prefix,
      sb.worker_filter as storage_bucket_worker_filter,
      sb.attributes as storage_bucket_attributes,
      sb.plugin_id as plugin_id,
      pl.name as plugin_name,
      pl.description as plugin_description,
      sbc.storage_bucket_id as storage_bucket_id,
      sbcms.secrets_encrypted as ct_secrets,
      sbcms.key_id as key_id

    from storage_bucket_credential sbc
    join storage_plugin_storage_bucket sb
      on sbc.storage_bucket_id = sb.public_id
    join plugin pl
      on sb.plugin_id = pl.public_id
    left join storage_bucket_credential_managed_secret sbcms
      on  sbc.private_id = sbcms.private_id;
  comment on view update_worker_storage_bucket_credential is
    'update_worker_storage_bucket_credential is used find workers using storage bucket credentials that need to be updated to the latest version.';

commit;