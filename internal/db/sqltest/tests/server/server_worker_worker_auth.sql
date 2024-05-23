-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
    select plan(9);
    select wtt_load('widgets', 'iam', 'kms');

    insert into server_worker
        (public_id, scope_id, type)
    values
        ('w_1234567891', 'global', 'pki');

    select is(count(*), 1::bigint) from server_worker where public_id = 'w_1234567891';

    -- Insert a worker auth record, expect it to be current
    insert into worker_auth_authorized
        (worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
    values
        ('key_id_1', 'w_1234567891', 'signing_pub_key_1', 'encryption_pub_key_1', 'controller_encryption_priv_key_1', 'kdkv___widget');

    select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_1' and state='current';

    -- Test rotation logic. Insert another worker auth record, expect it to be current.
    -- The previous record should be marked as previous
    insert into worker_auth_authorized
        (worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
    values
        ('key_id_2', 'w_1234567891', 'signing_pub_key_2', 'encryption_pub_key_2', 'controller_encryption_priv_key_2', 'kdkv___widget');
    select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_1' and state='previous';
    select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_2' and state='current';

    -- Perform an update, attempting to set key_id_1's state to current. This should fail
    select throws_ok($$ update worker_auth_authorized
        set state = 'current'
        where worker_key_identifier = 'key_id_1'$$);

    -- Perform an update, attempting to set key_id_2's state to previous. This should fail
    select throws_ok($$ update worker_auth_authorized
        set state = 'previous'
        where worker_key_identifier = 'key_id_2'$$);

    -- Delete key_id_2 and attempt to set key_id_1 to current. This should succeed
    delete from worker_auth_authorized
        where worker_key_identifier = 'key_id_2';
    update worker_auth_authorized
        set state = 'current'
        where worker_key_identifier = 'key_id_1';

    select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_1' and state='current';
    select is(count(*), 0::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_2';

    -- Attempt to set a bogus state. This should fail
    select throws_ok($$ update worker_auth_authorized
        set state = 'Alaska'
        where worker_key_identifier = 'key_id_1'$$);

    select * from finish();
rollback;
