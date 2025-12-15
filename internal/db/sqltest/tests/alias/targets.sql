-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(11);
select wtt_load('widgets', 'iam', 'kms', 'auth');

select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cb';

-- validate destination id and host id can be updated
prepare update_target_alias_destination as
    update alias_target
    set (destination_id, host_id) = ('t_________cg', 'h_________cg')
    where public_id = 'alt__t____cb';
select lives_ok('update_target_alias_destination');

select is(count(*), 1::bigint) from alias_target where value = 'blue.tcp.target';

prepare insert_case_insensitive_value_duplicate AS
    insert into alias_target (public_id, scope_id, value)
    values ('new_alias_for_tests', 'global', 'BLUE.TCP.TARGET');
select throws_like(
    'insert_case_insensitive_value_duplicate',
    'duplicate key value violates unique constraint "alias_value_uq"'
);

select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cb';
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cg' and host_id = 'h_________cg';

-- validate deleting a target nulls out the destination id and host id
prepare update_target_alias as
    delete from target_tcp
    where public_id = 't_________cg';
select lives_ok('update_target_alias');

select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cb';
select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cg';
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id is null and host_id is null;

-- validate a host id cant be set if the destination id is not set
prepare insert_destination_id_not_set_when_host_id_is_set as
    insert into alias_target (public_id, scope_id, value, host_id)
    values ('unset_destination_id', 'global', 'unset.destination.id', 'h_________cb');
select throws_like(
    'insert_destination_id_not_set_when_host_id_is_set',
    'new row for relation "alias_target" violates check constraint "destination_id_set_when_host_id_is_set"'
);

select * from finish();
rollback;
