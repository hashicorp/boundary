-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- alias tests triggers:
--  insert_alias_subtype
--  update_alias_subtype
--  delete_alias_subtype

begin;
select plan(17);
select wtt_load('widgets', 'iam', 'kms', 'auth');

-- validate the setup data
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb';
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cr';
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cg';

-- validate the insert triggers
prepare insert_target_alias as
    insert into alias_target
    (scope_id,     public_id,    value,   destination_id)
    values
        ('global',   'alt__t___2cb', 'second.blue.tcp.target', 't_________cb');
select lives_ok('insert_target_alias');

select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t___2cb';
select is(count(*), 1::bigint) from alias where public_id = 'alt__t___2cb';

-- validate the update triggers
prepare update_target_alias as
    update alias_target
    set value = 'updated.red.tcp.target.updated'
    where public_id = 'alt__t____cr';
select lives_ok('update_target_alias');

select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cr' and value = 'updated.red.tcp.target.updated';
select is(count(*), 1::bigint) from alias where public_id = 'alt__t____cr' and value = 'updated.red.tcp.target.updated';

-- validate delete_host_id_if_destination_id_is_null
update alias_target
    set host_id = 'hst_1234567890'
    where 
    public_id = 'alt__t____cr'
    or public_id = 'alt__tssh_cr';

select is(count(*), 2::bigint) from alias_target where host_id = 'hst_1234567890';

prepare delete_destination_target as
    delete from target_ssh
    where public_id = 'tssh______cr';
select lives_ok('delete_destination_target');

select is(count(*), 1::bigint) from alias_target where host_id = 'hst_1234567890';

prepare update_remove_destination_id as
    update alias_target
    set destination_id = null
    where public_id = 'alt__t____cr';

select lives_ok('update_remove_destination_id');

select is(count(*), 0::bigint) from alias_target where host_id = 'hst_1234567890';


-- validate the delete triggers
prepare delete_target_alias as
    delete
    from alias_target
    where public_id = 'alt__t____cg';
select lives_ok('delete_target_alias');

select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cg';
select is(count(*), 0::bigint) from alias where public_id = 'alt__t____cg';

select * from finish();
rollback;
