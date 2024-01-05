-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(10);
select wtt_load('widgets', 'iam', 'kms', 'auth');

select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cb';

-- validate destination id can be updated
prepare update_target_alias_destination as
    update alias_target
    set destination_id = 't_________cg'
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
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cg';

-- validate deleting a target nulls out the destination id
prepare update_target_alias as
    delete from target_tcp
    where public_id = 't_________cg';
select lives_ok('update_target_alias');

select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cb';
select is(count(*), 0::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id = 't_________cg';
select is(count(*), 1::bigint) from alias_target where public_id = 'alt__t____cb' and destination_id is null;

select * from finish();
rollback;
