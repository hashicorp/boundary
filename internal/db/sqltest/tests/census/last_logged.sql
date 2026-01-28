-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(6);

  select has_table('census_last_logged');
  select is(count(*), 1::bigint, 'census_last_logged should have only 1 row') from census_last_logged;
  select ok(not isfinite(last_logged_at)) from census_last_logged;

  prepare insert_row as
   insert into census_last_logged
    (last_logged_at)
   values
    (now());

  select throws_ok('insert_row', '23505',
    'duplicate key value violates unique constraint "census_last_logged_one_row"',
    'insert into census_last_logged should fail');

  prepare update_census_last_logged as
   update census_last_logged
      set last_logged_at = now();

  select lives_ok('update_census_last_logged');
  select ok(isfinite(last_logged_at)) from census_last_logged;

  select * from finish();

rollback;
