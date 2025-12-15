-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

drop view storage_plugin_storage_bucket_with_secret;

alter table storage_plugin_storage_bucket
  drop constraint if exists secrets_hmac_must_not_be_empty,
  alter column secrets_hmac drop not null;

-- Replaced in 88/01_storage_bucket_credential.up.sql
create view storage_plugin_storage_bucket_with_secret as
  select
    spsb.public_id,
    spsb.scope_id,
    spsb.name,
    spsb.description,
    spsb.create_time,
    spsb.update_time,
    spsb.version,
    spsb.plugin_id,
    spsb.bucket_name,
    spsb.bucket_prefix,
    spsb.worker_filter,
    spsb.attributes,
    spsb.secrets_hmac,
    spsbs.secrets_encrypted,
    spsbs.key_id
  from storage_plugin_storage_bucket spsb
  left join storage_plugin_storage_bucket_secret spsbs
    on spsbs.storage_bucket_id = spsb.public_id;
  comment on view storage_plugin_storage_bucket_with_secret is
    'storage_plugin_storage_bucket_with_secret is a view where each row contains a storage bucket. '
    'Encrypted secret and hmac value is not returned if a secret is not associated with the storage bucket.';

commit;