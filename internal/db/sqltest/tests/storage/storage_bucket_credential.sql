-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(5);
    select wtt_load('widgets', 'iam', 'kms');

    -- fail to create storage bucket without storage bucket credential
    prepare missing_storage_bucket_credential as
    insert into storage_plugin_storage_bucket
      (public_id,      scope_id, plugin_id,      bucket_name,        worker_filter)
    values
      ('sb_________1', 'global', 'pl__plg___sb', 'test bucket environmental', 'test worker filter');
    select throws_ok('missing_storage_bucket_credential', '23502');

    -- fail to create duplicate storage bucket credential environmental  
    prepare insert_duplicate_env_credential as
    insert into storage_bucket_credential_environmental
      (private_id, storage_bucket_id)
    values
      ('sbc___global', 'sb____global');
    select throws_ok('insert_duplicate_env_credential', '23505');

    -- create a managed secret SBC
    insert into storage_bucket_credential_managed_secret
      (private_id, storage_bucket_id, secrets_encrypted, key_id)
    values
      ('sbc________1', 'sb_________1', 'secret'::bytea, 'kdkv___widget');
    select is(count(*), 1::bigint) from storage_bucket_credential where private_id = 'sbc________1';

    insert into storage_plugin_storage_bucket
      (public_id,      scope_id, plugin_id,      bucket_name,        worker_filter,        secrets_hmac, storage_bucket_credential_id)
    values
      ('sb_________1', 'global', 'pl__plg___sb', 'test bucket name', 'test worker filter', '\xdeadbeef', 'sbc________1');
    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________1';

    -- fail to create duplicate storage bucket credential managed secret
    prepare insert_duplicate_managed_secret_credential as
    insert into storage_bucket_credential_managed_secret
      (private_id, storage_bucket_id, secrets_encrypted, key_id)
    values
      ('sbc________1', 'sb_________1', 'secret'::bytea, 'kdkv___widget');
    select throws_ok('insert_duplicate_managed_secret_credential', '23505');

    select * from finish();
rollback;
