-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(10);

  select has_domain('wt_url_safe_id');
  select domain_type_is('wt_url_safe_id', 'text');

  create table test_table (
    id wt_url_safe_id primary key
  );

  prepare insert_valid_ids as
    insert into test_table
    values ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~-._'),
           ('__________a'), ('__________1'), ('__________~'), ('__________-'), ('__________.'), ('___________');

  select lives_ok('insert_valid_ids', 'Inserting IDs with valid characters should not cause an error');

  prepare insert_slash as insert into test_table values ('/0123456789');
  select throws_like('insert_slash', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Inserting an ID with the "/" character should cause an error');

  prepare insert_plus as insert into test_table values ('+0123456789');
  select throws_like('insert_plus', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Inserting an ID with the "+" character should cause an error');

  prepare insert_equals as insert into test_table values ('=0123456789');
  select throws_like('insert_equals', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Inserting an ID with the "=" character should cause an error');

  prepare insert_percent as insert into test_table values ('%0123456789');
  select throws_like('insert_percent', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Inserting an ID with the "%" character should cause an error');

  prepare insert_empty as insert into test_table values ('           ');
  select throws_like('insert_empty', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Inserting an empty ID should cause an error');

  prepare update_to_invalid as
    update test_table
       set id = '/0123456789'
     where id = '__________a';
  select throws_like('update_to_invalid', '%"wt_url_safe_id_can_only_contain_unreserved_characters"', 'Changing an ID to an invalid character should cause an error');

  prepare update_to_valid as
    update test_table
       set id = '0123456789a'
     where id = '__________a';
  select lives_ok('update_to_valid', 'Changing an ID to another valid ID should not cause an error');
  select * from finish();
rollback;
