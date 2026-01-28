-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(15);
select wtt_load('widgets', 'iam', 'kms');

insert into server_worker
(public_id, scope_id, type)
values
    ('w_1234567891', 'global', 'pki');

insert into server_worker
(public_id, scope_id, type)
values
    ('w_9876543210', 'global', 'pki');

select is(count(*), 1::bigint) from server_worker where public_id = 'w_1234567891';
select is(count(*), 1::bigint) from server_worker where public_id = 'w_9876543210';

-- Insert worker auth records, expect them to be current
insert into worker_auth_authorized
(worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
values
    ('key_id_w11', 'w_1234567891', 'signing_pub_key_w11', 'encryption_pub_key_w11', 'controller_encryption_priv_key_w11', 'kdkv___widget');
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w11' and state='current';

insert into worker_auth_authorized
(worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
values
    ('key_id_w21', 'w_9876543210', 'signing_pub_key_w21', 'encryption_pub_key_w21', 'controller_encryption_priv_key_w21', 'kdkv___widget');
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w21' and state='current';

-- Test rotation logic. Insert another worker auth record, expect it to be current.
-- The previous record should be marked as previous
insert into worker_auth_authorized
(worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
values
    ('key_id_w12', 'w_1234567891', 'signing_pub_key_w12', 'encryption_pub_key_w12', 'controller_encryption_priv_key_w12', 'kdkv___widget');
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w11' and state='previous';
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w12' and state='current';

insert into worker_auth_authorized
(worker_key_identifier, worker_id, worker_signing_pub_key, worker_encryption_pub_key, controller_encryption_priv_key, key_id)
values
    ('key_id_w22', 'w_9876543210', 'signing_pub_key_w22', 'encryption_pub_key_w22', 'controller_encryption_priv_key_w22', 'kdkv___widget');
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w21' and state='previous';
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w22' and state='current';

-- Perform an update, attempting to set key_id_w11's state to current. This should fail
select throws_ok($$ update worker_auth_authorized
        set state = 'current'
        where worker_key_identifier = 'key_id_w11'$$);

-- Perform an update, attempting to set key_id_w12's state to previous. This should fail
select throws_ok($$ update worker_auth_authorized
        set state = 'previous'
        where worker_key_identifier = 'key_id_w12'$$);

-- Delete key_id_2 and attempt to set key_id_1 to current. This should succeed
delete from worker_auth_authorized
where worker_key_identifier = 'key_id_w12';
update worker_auth_authorized
set state = 'current'
where worker_key_identifier = 'key_id_w11';

select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w11' and state='current';
select is(count(*), 0::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w12';

-- The other worker auth records are unaffected
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w21' and state='previous';
select is(count(*), 1::bigint) from worker_auth_authorized where worker_key_identifier = 'key_id_w22' and state='current';

-- Attempt to set a bogus state. This should fail
select throws_ok($$ update worker_auth_authorized
        set state = 'Alaska'
        where worker_key_identifier = 'key_id_w11'$$);

select * from finish();
rollback;