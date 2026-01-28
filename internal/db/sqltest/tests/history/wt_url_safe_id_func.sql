-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(7);
  -- Verify the function exists and is declared properly
  select has_function('wt_url_safe_id');
  select volatility_is('wt_url_safe_id', 'volatile');
  select isnt_strict('wt_url_safe_id');

  create table test_table (
    id wt_url_safe_id default wt_url_safe_id() primary key,
    test_num integer not null
  );

  create function test_setup_data(count integer) returns integer
  as $$
  begin
    for i in 1..count loop
      insert into test_table (test_num) values (i);
    end loop;
    return count;
  end;
  $$ language plpgsql;

  select is(test_setup_data(100000), 100000);
  select is(count(*), 100000::bigint, 'test_table should have 100000 rows') from test_table;
  select is(count(*), 0::bigint, 'no id should be longer than 14 characters')
            from test_table where length(id) > 14;
  select is(count(*), 0::bigint, 'no id should be shorter than 14 characters')
            from test_table where length(id) < 14;

  select * from finish();
rollback;
