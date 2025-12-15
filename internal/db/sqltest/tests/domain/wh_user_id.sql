-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(3);

  create table test_wh_user_id (
    id wh_user_id
  );

  prepare too_short as
    insert into test_wh_user_id (id)
         values ('short');
  select throws_ok(
    'too_short',
    '23514',
    'value for domain wh_user_id violates check constraint "wh_user_id_check"'
  );
  prepare too_short_trim as
    insert into test_wh_user_id (id)
         values ('     short     ');
  select throws_ok(
    'too_short_trim',
    '23514',
    'value for domain wh_user_id violates check constraint "wh_user_id_check"'
  );

  prepare valid as
    insert into test_wh_user_id (id)
         values ('u_123456789'),
                ('u_anon'),
                ('u_auth'),
                ('u_recovery');
  select lives_ok('valid');

  select * from finish();
rollback;
