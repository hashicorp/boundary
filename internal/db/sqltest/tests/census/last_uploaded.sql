-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(7);

  select has_table('census_last_uploaded');
  select is(count(*), 2::bigint, 'census_last_uploaded should have only 2 row') from census_last_uploaded;
  select results_eq(
           $$
           select last_uploaded_at::timestamptz, metric
             from census_last_uploaded
           $$,
           $$
           values ('-infinity'::timestamptz, 'sessions'),
                  ('-infinity'::timestamptz, 'active_users')
           $$);


  prepare insert_row as
   insert into census_last_uploaded
          (last_uploaded_at, metric)
   values (now(), 'sessions');

  select throws_ok('insert_row',
                   '23505',
                   'duplicate key value violates unique constraint "census_last_uploaded_pkey"',
                   'insert into census_last_uploaded should fail');

  prepare insert_row_invalid_metric as
   insert into census_last_uploaded
          (last_uploaded_at, metric)
   values (now(), 'foo');

  select throws_ok('insert_row_invalid_metric',
                   '23503',
                   'insert or update on table "census_last_uploaded" violates foreign key constraint "census_metric_enm_fkey"',
                   'insert into census_last_uploaded should fail');

  prepare update_census_last_uploaded as
   update census_last_uploaded
      set last_uploaded_at = now();

  select lives_ok('update_census_last_uploaded');
  select results_eq(
           $$
           select last_uploaded_at::timestamptz, metric
             from census_last_uploaded
           $$,
           $$
           values (now(), 'sessions'),
                  (now(), 'active_users')
           $$);

  select * from finish();

rollback;
