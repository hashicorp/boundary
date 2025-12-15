-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(5);

  create table test_t1 (
    id text
  );
  insert into test_t1 (id) values ('one');

  create trigger immutable_table before insert or update or delete
    on test_t1 for each row execute procedure immutable_table();

  select is(count(*), 1::bigint) from test_t1;

  prepare insert_fail as insert into test_t1 (id) values ('two');
  select throws_ok('insert_fail', '23603');

  prepare update_fail as
    update test_t1
       set id = 'two'
     where id = 'one';
  select throws_ok('update_fail', '23603');

  prepare delete_fail as delete from test_t1;
  select throws_ok('delete_fail', '23603');

  select is(count(*), 1::bigint) from test_t1;

  select * from finish();
rollback;
