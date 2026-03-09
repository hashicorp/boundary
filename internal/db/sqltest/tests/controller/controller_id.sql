-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- controller_id tests:
--  validates the wt_controller_id domain

begin;
  select plan(8);

  select has_domain('wt_controller_id');
  
  create table controller_id_testing (
    id wt_controller_id
  );

  prepare empty_insert as insert into controller_id_testing (id) values ('');
  SELECT throws_like(
    'empty_insert',
    '%"wt_controller_id_check"',
    'We should error for empty controller id'
  );
  
  prepare null_insert as insert into controller_id_testing (id) values (null);
  select lives_ok('null_insert');
  select is(count(*), 1::bigint) from controller_id_testing where id is null;

  prepare valid_insert as insert into controller_id_testing (id) values ('test-controller-id');
  select lives_ok('valid_insert');
  select is(count(*), 1::bigint) from controller_id_testing where id = 'test-controller-id';
  
  prepare short_insert as insert into controller_id_testing (id) values ('_');
  select lives_ok('short_insert');
  select is(count(*), 1::bigint) from controller_id_testing where id = '_';

  select * from finish();
rollback;
