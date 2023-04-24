-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
    select plan(4);

    -- Ensure no data has been added
    select is(count(*), 0::bigint) from storage_bucket;
    select is(count(*), 0::bigint) from storage_plugin_storage_bucket;

    -- Insert records into plugins storage_plugin_storage_bucket
    insert into plugin
        (scope_id, public_id, name)
    values
        ('global', 'plg____sb-plg', 'Storage Bucket Plugin');

	insert into plugin_storage_supported
        (public_id)
    values
        ('plg____sb-plg');

    insert into storage_plugin_storage_bucket
    	(public_id, scope_id, plugin_id, bucket_name, worker_filter, secrets_hmac)
    values
        ('sb_________1','global', 'plg____sb-plg', 'test bucket name', 'test worker filter', '\xdeadbeef');

    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________1';
    select is(count(*), 1::bigint) from storage_bucket where public_id = 'sb_________1';

    select * from finish();
rollback;