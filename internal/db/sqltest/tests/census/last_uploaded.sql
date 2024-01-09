-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(6);

  select has_table('census_last_uploaded');
  select is(count(*), 1::bigint, 'census_last_uploaded should have only 1 row') from census_last_uploaded;
  select ok(not isfinite(last_uploaded_at)) from census_last_uploaded;

  prepare insert_row as
   insert into census_last_uploaded
    (last_uploaded_at)
   values
    (now());

  select throws_ok('insert_row', '23505',
    'duplicate key value violates unique constraint "census_last_uploaded_one_row"',
    'insert into census_last_uploaded should fail');

  prepare update_census_last_uploaded as
   update census_last_uploaded
      set last_uploaded_at = now();

  select lives_ok('update_census_last_uploaded');
  select ok(isfinite(last_uploaded_at)) from census_last_uploaded;

  select * from finish();

rollback;
