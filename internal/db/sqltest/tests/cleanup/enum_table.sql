-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  select plan(3);

  select has_table('deletion_tables_enm');
  select is(count(*), 19::bigint, 'deletion_tables_enm should have 19 rows') from deletion_tables_enm;
  select throws_ok('insert into deletion_tables_enm (name) values ("incorrect_table")', 42703, null, 'column "incorrect_table" does not exist');

  select * from finish();

rollback;
