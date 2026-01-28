-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(4);

    -- Ensure test data is correct
    select is(count(*), 2::bigint) from storage_plugin_storage_bucket;

    -- insert storage bucket credential
    insert into storage_bucket_credential_environmental
      (private_id, storage_bucket_id)
    values
      ('sbc________1', 'sb_________1'),
      ('sbc________2', 'sb_________2');

    -- insert global storage bucket
    insert into storage_plugin_storage_bucket
      (public_id,      scope_id, plugin_id,      bucket_name,        worker_filter,        secrets_hmac, storage_bucket_credential_id)
    values
      ('sb_________1', 'global', 'pl__plg___sb', 'test bucket name', 'test worker filter', '\xdeadbeef', 'sbc________1');

    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________1';

    -- insert org storage bucket
    insert into storage_plugin_storage_bucket
      (public_id,      scope_id,       plugin_id,      bucket_name,        worker_filter,        secrets_hmac, storage_bucket_credential_id)
    values
      ('sb_________2', 'o_____colors', 'pl__plg___sb', 'test bucket name', 'test worker filter', '\xdeadbeef', 'sbc________2');

    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________2';

    -- Try to insert row with a project scope id
    prepare invalid_storage_bucket as
    insert into storage_plugin_storage_bucket
      (public_id,      scope_id,       plugin_id,      bucket_name,        worker_filter,        secrets_hmac)
    values
      ('sb_________3', 'p____bcolors', 'pl__plg___sb', 'test bucket name', 'test worker filter', '\xdeadbeef');
    select throws_ok('invalid_storage_bucket', null, null, 'insert invalid storage_bucket succeeded');

    select * from finish();
rollback;
